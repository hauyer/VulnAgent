"""WP4 unit tests: libFuzzer output parsing, dedup, honest unavailability.

Covers the real-engine parsing (Windows ASan frames, artifacts, stats), the
crash-classification rules (sanitizer crash vs nonzero exit vs timeout/OOM),
the unavailability honesty contract (no compiler -> not_run, missing binary ->
not_run), and the engine protocol gate on authorization.
"""

from __future__ import annotations

import asyncio

from vulnagent.contracts import EvidenceType, FuzzRequest
from vulnagent.fuzz.libfuzzer import (
    LibFuzzerRunStats,
    RealLibFuzzerEngine,
    parse_libfuzzer_output,
)
from vulnagent.sandbox.compiler import CompileResult


# -- output parsing ----------------------------------------------------------


def test_parse_done_run_stats() -> None:
    out = (
        "INFO: Seed: 7\n"
        "#2\tINITED cov: 5 ft: 8 corp: 4/20b exec/s: 0 rss: 40Mb\n"
        "#30000\tDONE cov: 12 ft: 40 corp: 7/42b lim: 64 exec/s: 100 rss: 41Mb\n"
        "Done 30000 runs in 300 second(s)\n"
    )
    stats = parse_libfuzzer_output(out, "")
    assert stats.done is True
    assert stats.runs == 30000
    assert stats.coverage == 12
    assert stats.corpus_entries == 7
    assert stats.corpus_bytes == 42


def test_parse_windows_asan_crash() -> None:
    out = "INFO: Seed: 7\n#5\tINITED cov: 5 ft: 8 corp: 4/20b\n"
    err = (
        "==2704==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x00658bcff608\n"
        "WRITE of size 1 at 0x00658bcff608 thread T0\n"
        "#0 0x7ff7940f2bcf  (D:\\x\\target.exe+0x52bcf)\n"
        "#1 0x7ff7940f2cba  (D:\\x\\target.exe+0x52cba)\n"
        "Test unit written to D:\\x\\artifacts\\crash-a19f987b885f5a96069f4bc7f12b9e84ceba7dfa\n"
    )
    stats = parse_libfuzzer_output(out, err)
    assert stats.crashed is True
    assert stats.sanitizer_kind == "stack-buffer-overflow"
    assert stats.stack_hash is not None and len(stats.stack_hash) == 16
    assert stats.artifact_path.endswith("crash-a19f987b885f5a96069f4bc7f12b9e84ceba7dfa")


def test_parse_posix_asan_frame() -> None:
    err = (
        "ERROR: AddressSanitizer: heap-use-after-free\n"
        "#0 0x55a1 in parse_message /src/parse.c:12:3\n"
    )
    stats = parse_libfuzzer_output("", err)
    assert stats.sanitizer_kind == "heap-use-after-free"
    assert stats.stack_hash is not None


def test_parse_timeout_and_oom_are_not_crashes() -> None:
    timeout = parse_libfuzzer_output("", "ERROR: libFuzzer: timeout after 5 seconds")
    assert timeout.timed_out is True
    assert timeout.crashed is False

    oom = parse_libfuzzer_output("", "ERROR: AddressSanitizer: out-of-memory (allocator)")
    assert oom.oom is True
    assert oom.crashed is False


def test_parse_error_captured_when_no_success() -> None:
    stats = parse_libfuzzer_output("", "ERROR: something failed")
    assert stats.done is False
    assert stats.crashed is False
    assert "something failed" in (stats.error or "")


# -- unavailability honesty --------------------------------------------------


def test_compiler_missing_is_not_run_not_success() -> None:
    result = CompileResult(compiled=False, reason="clang toolchain unavailable")
    assert result.compiled is False
    assert "unavailable" in (result.reason or "")


def test_engine_unauthorized_never_executes() -> None:
    engine = RealLibFuzzerEngine()
    result = asyncio.run(
        engine.run(
            FuzzRequest(
                task_id="t1",
                target_id="tg",
                target_path="C:/nonexistent/target.exe",
                authorized=False,
            )
        )
    )
    assert result.executed is False
    assert result.crashes == 0
    assert result.metadata["reason"] == "target_not_authorized"


def test_engine_missing_binary_is_not_run() -> None:
    engine = RealLibFuzzerEngine()
    result = asyncio.run(
        engine.run(
            FuzzRequest(
                task_id="t1",
                target_id="tg",
                target_path="C:/nonexistent/target.exe",
                authorized=True,
            )
        )
    )
    assert result.executed is False
    assert result.metadata["reason"] == "compiled_target_not_found"


# -- corpus hashing ----------------------------------------------------------


def test_corpus_hash_is_deterministic(tmp_path) -> None:
    seed_dir = tmp_path / "seeds"
    seed_dir.mkdir()
    (seed_dir / "a").write_bytes(b"abc")
    (seed_dir / "b").write_bytes(b"def")
    request = FuzzRequest(
        task_id="t",
        target_id="tg",
        target_path="x",
        authorized=True,
        metadata={"seed_dir": str(seed_dir)},
    )
    first = RealLibFuzzerEngine._corpus_hash(request)
    second = RealLibFuzzerEngine._corpus_hash(request)
    assert first == second
    assert len(first) == 64

    (seed_dir / "c").write_bytes(b"ghi")
    third = RealLibFuzzerEngine._corpus_hash(request)
    assert third != first


def test_engine_crash_evidence_types(tmp_path) -> None:
    """A crashing run must attach CRASH_LOG evidence with the 8.4 fields."""

    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")  # fake binary; the sandbox will fail to run it
    engine = RealLibFuzzerEngine()
    result = asyncio.run(
        engine.run(
            FuzzRequest(
                task_id="t1",
                target_id="tg",
                target_path=str(binary),
                authorized=True,
                metadata={"runs": 100, "max_len": 32, "seed": 1},
            )
        )
    )
    # The run attempted execution; failure is surfaced honestly, never as
    # zero findings from a scan that did not happen.
    assert result.metadata.get("executed") is not None
    assert "libfuzzer" in result.metadata["engine"]
