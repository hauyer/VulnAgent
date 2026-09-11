"""Tests for P4 optional adapters, bounded signals, and artifact persistence."""

import json
import math
import subprocess
import threading
from pathlib import Path

import pytest
import vulnagent.analyzers.binary.reverse.artifacts as artifacts_module

from vulnagent.analyzers.binary.common import inspect_packing_signals
from vulnagent.analyzers.binary.reverse import (
    BinaryArtifactStore,
    Radare2Adapter,
    ToolRunResult,
    UpxAdapter,
    parse_radare2_json,
)
from vulnagent.contracts import BinaryAnalysisResult


def result(**metadata: object) -> BinaryAnalysisResult:
    return BinaryAnalysisResult(
        task_id="task/a",
        target_id="target:b",
        path="sample.bin",
        imports=["kernel!x"],
        metadata=metadata,
    )


def test_packing_signals_are_bounded_and_not_a_verdict() -> None:
    inspected = inspect_packing_signals(
        result(
            entry_point=0x1010,
            sections=[
                {"name": "UPX1", "address": 0x1000, "virtual_size": 0x100, "entropy": 7.8},
                {"name": "normal", "entropy": "untrusted"},
            ],
        )
    )
    assert inspected["signal_score"] == 100
    assert {"high_entropy_section", "packer_section_name", "low_import_count", "entry_point_in_high_entropy_section"} <= set(inspected["signals"])
    assert "not a packing" in inspected["limitations"][0]
    assert json.loads(json.dumps(inspected)) == inspected


def test_upx_requires_authorization_and_handles_missing_tool(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"not run")
    calls: list[object] = []
    adapter = UpxAdapter(which=lambda _: None, runner=lambda *args, **kwargs: calls.append((args, kwargs)))
    assert adapter.inspect(path).status == "not_authorized"
    unavailable = adapter.inspect(path, authorized=True)
    assert unavailable.status == "unavailable"
    assert calls == []


def test_upx_runs_argument_vector_with_timeout_and_no_shell(tmp_path: Path) -> None:
    path = tmp_path / "input;not-a-command.bin"
    path.write_bytes(b"data")
    received: dict[str, object] = {}

    def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        received["args"] = args
        received["kwargs"] = kwargs
        return subprocess.CompletedProcess(args[0], 0, "listed", "")

    run = UpxAdapter(which=lambda _: "/mock/upx", timeout_seconds=2.5, runner=runner).inspect(path, authorized=True)
    assert run.status == "ok" and run.executed is True
    assert received["args"] == (["/mock/upx", "-l", str(path)],)
    assert received["kwargs"] == {"check": False, "capture_output": True, "text": True, "timeout": 2.5, "shell": False}
    assert run.facts and run.facts["input"]["sha256"]


def test_upx_timeout_is_a_safe_result(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"data")

    def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    assert UpxAdapter(which=lambda _: "/mock/upx", runner=runner).inspect(path, authorized=True).status == "timeout"


def test_upx_unpack_uses_fresh_output_and_fingerprints_it(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    original = b"compressed"
    path.write_bytes(original)

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[1:3] == ["-d", "-o"] and command[-1] == str(path)
        Path(command[3]).write_bytes(b"unpacked")
        return subprocess.CompletedProcess(command, 0, "ok", "")

    run = UpxAdapter(which=lambda _: "/mock/upx", runner=runner).unpack(path, output_dir=tmp_path / "out", authorized=True)
    assert run.status == "ok" and path.read_bytes() == original
    assert run.facts and run.facts["output"]["size_bytes"] == len(b"unpacked")
    assert Path(run.facts["output_path"]).is_file()


def test_upx_unpack_rejects_oversized_or_missing_output(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"input")

    def oversized(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        Path(command[3]).write_bytes(b"too large")
        return subprocess.CompletedProcess(command, 0, "", "")

    run = UpxAdapter(which=lambda _: "/mock/upx", runner=oversized).unpack(path, output_dir=tmp_path / "out", authorized=True, max_output_bytes=2)
    assert run.status == "output_too_large"
    missing = UpxAdapter(which=lambda _: "/mock/upx", runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", "")).unpack(path, output_dir=tmp_path / "other", authorized=True)
    assert missing.status == "output_error"


def test_radare2_missing_tool_never_runs(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"data")
    adapter = Radare2Adapter(which=lambda _: None)
    assert adapter.inspect(path, authorized=True).status == "unavailable"
    assert adapter.inspect(path).status == "not_authorized"


def test_radare2_accepts_valid_empty_function_list(tmp_path: Path) -> None:
    path = tmp_path / "managed.exe"
    path.write_bytes(b"MZmanaged")
    commands: list[list[str]] = []

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "[]", "")

    run = Radare2Adapter(which=lambda _: "/mock/r2", runner=runner).inspect(
        path, authorized=True
    )

    assert run.status == "ok"
    assert run.facts and run.facts["functions"] == []
    assert run.facts["cfg"] == {}
    assert len(commands) == 1


def test_radare2_accepts_addr_fields_from_version_6_json(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"data")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        source = command[3]
        if "aflj" in source:
            text = '[{"addr":4096,"name":"main","size":32}]'
        elif "agfj" in source:
            text = '[{"addr":4096,"blocks":[{"addr":4096,"jump":4112}]}]'
        else:
            text = "int main(void) { return 0; }"
        return subprocess.CompletedProcess(command, 0, text, "")

    run = Radare2Adapter(which=lambda _: "/mock/r2", runner=runner).inspect(
        path, authorized=True
    )

    assert run.status == "ok"
    assert run.facts and run.facts["functions"][0]["address"] == 4096
    assert run.facts["cfg"] == {"0x1000": ["0x1010"]}


def test_radare2_uses_separate_commands_and_correct_block_adjacency(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"data")
    commands: list[list[str]] = []

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        source = command[3]
        if "aflj" in source:
            text = '[{"offset":4096,"name":"main","size":32}]'
        elif "agfj" in source:
            text = '[{"offset":4096,"blocks":[{"offset":4096,"jump":4112,"fail":4128},{"offset":4112}]}]'
        elif "pdc @ 0x1000" in source:
            text = "int main(void) { return 0; }"
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, text, "")

    run = Radare2Adapter(which=lambda _: "/mock/r2", timeout_seconds=3, runner=runner).inspect(path, authorized=True)
    assert run.status == "ok"
    assert run.facts == {
        "input": {"sha256": run.facts["input"]["sha256"], "size_bytes": 4},
        "functions": [{"name": "main", "address": 4096, "size": 32, "source": "radare2"}],
        "cfg": {"0x1000": ["0x1010", "0x1020"], "0x1010": []},
        "pseudocode": {"0x1000": "int main(void) { return 0; }"},
        "pseudocode_failures": [],
        "source": "radare2",
    }
    assert [command[3] for command in commands] == ["aa;aflj", "aa;agfj", "aa;pdc @ 0x1000"]
    assert all(command[:3] == ["/mock/r2", "-q", "-c"] and command[-1] == str(path) for command in commands)


def test_radare2_nonzero_invalid_and_pdc_failure_are_safe(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"data")
    nonzero = Radare2Adapter(which=lambda _: "/mock/r2", runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 2, "bad", "err")).inspect(path, authorized=True)
    assert nonzero.status == "error"
    invalid = Radare2Adapter(which=lambda _: "/mock/r2", runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "not json", "")).inspect(path, authorized=True)
    assert invalid.status == "invalid_output"

    def pdc_failure(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "aflj" in command[3]:
            return subprocess.CompletedProcess(command, 0, '[{"offset":1}]', "")
        if "agfj" in command[3]:
            return subprocess.CompletedProcess(command, 0, '[{"blocks":[{"offset":1}]}]', "")
        return subprocess.CompletedProcess(command, 1, "", "pdc unavailable")

    partial = Radare2Adapter(which=lambda _: "/mock/r2", runner=pdc_failure).inspect(path, authorized=True)
    assert partial.status == "partial" and partial.facts and partial.facts["pseudocode_failures"][0]["address"] == 1


def test_radare2_parser_bounds_and_compatibility_parser() -> None:
    with pytest.raises(ValueError, match="positive"):
        parse_radare2_json("[]" + "\0" + "[]", 0)
    with pytest.raises(ValueError, match="exactly"):
        parse_radare2_json("[]")
    facts = parse_radare2_json('[{"offset":1},{"offset":"bad"}]' + "\0" + '[{"blocks":[{"offset":1,"jump":2}]}]', 1)
    assert facts["functions"] == [{"name": "fcn.1", "address": 1, "size": 0, "source": "radare2"}]
    assert facts["cfg"] == {"0x1": ["0x2"]}


def test_artifact_store_uses_collision_resistant_id_and_validated_index(tmp_path: Path) -> None:
    store = BinaryArtifactStore(tmp_path / "artifacts")
    saved = store.save_result(result(answer={"safe": True}), extra={"tool": ToolRunResult("x", "unavailable").as_dict()})
    assert saved.name.startswith("task_a-target_b-") and saved.suffix == ".json"
    artifact_id = saved.stem
    assert not list(saved.parent.glob("*.tmp"))
    loaded = store.load(artifact_id)
    assert loaded is not None and loaded["result"]["metadata"]["answer"] == {"safe": True}
    assert store.list_by_task("task/a") == [{"artifact_id": artifact_id, "path": saved.name, "task_id": "task/a", "target_id": "target:b"}]
    assert json.loads((saved.parent / "index.json").read_text())["artifacts"]


def test_artifact_store_rejects_non_json_and_invalid_index(tmp_path: Path) -> None:
    store = BinaryArtifactStore(tmp_path)
    with pytest.raises(ValueError, match="serializable"):
        store.save_result(result(), extra={"bad": {1, 2}})
    with pytest.raises(ValueError, match="non-finite"):
        store.save_result(result(), extra={"bad": math.nan})
    (tmp_path / "index.json").write_text('{"artifact_version":2,"artifacts":[{"artifact_id":"../bad","path":"../bad.json","task_id":"a","target_id":"b"}]}')
    with pytest.raises(ValueError, match="invalid artifact index"):
        store.list_by_task("a")


def test_artifact_store_in_process_lock_preserves_concurrent_entries(tmp_path: Path) -> None:
    store = BinaryArtifactStore(tmp_path)
    errors: list[BaseException] = []

    def save(index: int) -> None:
        try:
            store.save_result(BinaryAnalysisResult(task_id=f"task-{index}", target_id=f"target-{index}", path="sample"))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=save, args=(index,)) for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(json.loads((tmp_path / "index.json").read_text())["artifacts"]) == 12


def test_artifact_store_retries_transient_windows_replace_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_replace = artifacts_module.os.replace
    attempts = 0

    def transient_replace(source: str, destination: str | Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError("transient sharing violation")
        real_replace(source, destination)

    monkeypatch.setattr(artifacts_module.os, "replace", transient_replace)
    saved = BinaryArtifactStore(tmp_path).save_result(result())

    assert saved.is_file()
    assert attempts >= 4  # artifact and index replacements, including two retries
