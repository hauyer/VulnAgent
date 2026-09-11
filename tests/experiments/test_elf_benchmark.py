"""Tests for the real-ELF benchmark boundary without executing a target."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import run_elf_benchmark


ROOT = Path(__file__).resolve().parents[2]


def test_elf_manifest_is_paired_and_authorized() -> None:
    manifest = run_elf_benchmark.load_manifest(ROOT / "benchmarks" / "elf" / "manifest.json")
    samples = manifest["samples"]

    assert len(samples) == 6
    assert {sample["expected_format"] for sample in samples} == {"ELF"}
    assert sum(sample["ground_truth"] == "vulnerable" for sample in samples) == 3
    assert sum(sample["ground_truth"] == "clean" for sample in samples) == 3
    assert all("self-authored" in sample["source"] for sample in samples)


@pytest.mark.parametrize(
    ("profile", "required", "forbidden"),
    [
        ("symbol-rich", {"-no-pie"}, {"-s", "-fPIE"}),
        ("stripped", {"-no-pie", "-s"}, {"-fPIE"}),
        ("pie", {"-fPIE", "-pie"}, {"-s", "-no-pie"}),
    ],
)
def test_elf_profiles_control_compilation_flags(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile: str,
    required: set[str],
    forbidden: set[str],
) -> None:
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        commands.append(command)
        Path(command[-1]).write_bytes(b"\x7fELFfixture")
        return SimpleNamespace(returncode=0, stderr=b"")

    monkeypatch.setattr(run_elf_benchmark.subprocess, "run", fake_run)
    flags = next(flags for _, flags, name in run_elf_benchmark._PROFILES if name == profile)
    run_elf_benchmark._compile_elf(
        tmp_path / "fixture.c",
        tmp_path / f"{profile}.elf",
        "gcc",
        flags,
    )

    assert required.issubset(commands[0])
    assert forbidden.isdisjoint(commands[0])
    assert commands[0][-2] == "-o"


def test_elf_compiler_output_is_verified(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        Path(command[-1]).write_bytes(b"MZ-not-elf")
        return SimpleNamespace(returncode=0, stderr=b"")

    monkeypatch.setattr(run_elf_benchmark.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="did not produce ELF"):
        run_elf_benchmark._compile_elf(
            tmp_path / "fixture.c",
            tmp_path / "fixture.elf",
            "gcc",
            ("-O0",),
        )


def test_zig_compiler_uses_explicit_linux_gnu_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        commands.append(command)
        Path(command[-1]).write_bytes(b"\x7fELFfixture")
        return SimpleNamespace(returncode=0, stderr=b"")

    monkeypatch.setattr(run_elf_benchmark.subprocess, "run", fake_run)
    run_elf_benchmark._compile_elf(
        tmp_path / "fixture.c",
        tmp_path / "fixture.elf",
        "zig.exe",
        ("-O0", "-no-pie"),
    )

    assert commands[0][:4] == ["zig.exe", "cc", "-target", "x86_64-linux-gnu"]
    assert run_elf_benchmark._compiler_machine("zig.exe") == "x86_64-linux-gnu"


def test_known_windows_compiler_target_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        run_elf_benchmark,
        "_compiler_machine",
        lambda _: "x86_64-w64-mingw32",
    )

    with pytest.raises(RuntimeError, match="does not produce ELF"):
        run_elf_benchmark._require_elf_compiler("gcc")


def test_elf_manifest_rejects_unpaired_family(tmp_path: Path) -> None:
    source = ROOT / "benchmarks" / "elf" / "manifest.json"
    manifest = json.loads(source.read_text(encoding="utf-8"))
    manifest["samples"] = manifest["samples"][:-1]
    changed = tmp_path / "manifest.json"
    changed.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="must pair"):
        run_elf_benchmark.load_manifest(changed)


def test_elf_summary_states_non_execution_and_small_sample_boundary() -> None:
    summary = run_elf_benchmark.render_summary(
        [
            {
                "method": "vulnagent_elf_stripped",
                "samples": 6,
                "true_positive": 3,
                "false_positive": 0,
                "true_negative": 3,
                "false_negative": 0,
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
                "evidence_chain_coverage": 1.0,
            }
        ],
        {
            "generated_at": "2026-09-11T00:00:00Z",
            "compiler_version": "0.16.0",
            "compiler_machine": "x86_64-linux-gnu",
            "fixture_count": 6,
            "family_count": 3,
            "row_count": 18,
        },
    )

    assert "未执行任何 ELF 目标" in summary
    assert "Wilson 下界" in summary
    assert "UNCERTAIN" in summary
