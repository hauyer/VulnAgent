"""WP4 integration: real libFuzzer/ASan closed loop (conditionally executed).

When a real clang toolchain is available, this test compiles the cp_parse
case, runs the engine through the sandbox and asserts the development-guide
8.4 gate: an authorized crash with reproducible input, independent replay
and a clean fixed-version outcome. Without clang the test skips with an
explicit reason (honest unavailability, not a silent pass).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml

from vulnagent.contracts import EvidenceType, FuzzRequest
from vulnagent.fuzz.libfuzzer import RealLibFuzzerEngine
from vulnagent.sandbox.compiler import (
    compile_libfuzzer_target,
    locate_clang,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CASE_DIR = REPO_ROOT / "benchmarks" / "dynamic" / "libfuzzer" / "cp_parse"

pytestmark = pytest.mark.asyncio


def _clang_available() -> bool:
    return locate_clang() is not None


@pytest.mark.skipif(
    not _clang_available(),
    reason="clang toolchain unavailable; set VULNAGENT_CLANG or install LLVM",
)
async def test_real_libfuzzer_closed_loop(tmp_path: Path) -> None:
    manifest = yaml.safe_load((CASE_DIR / "manifest.yaml").read_text(encoding="utf-8"))
    compile_spec = manifest["compile"]
    clang = locate_clang()

    vuln_build = compile_libfuzzer_target(
        CASE_DIR / compile_spec["vuln_source"],
        tmp_path / "vuln",
        clang=clang,
        opt_level=compile_spec["flags"][0],
    )
    fix_build = compile_libfuzzer_target(
        CASE_DIR / compile_spec["fix_source"],
        tmp_path / "fix",
        clang=clang,
        opt_level=compile_spec["flags"][0],
    )

    assert vuln_build.compiled, vuln_build.reason
    assert fix_build.compiled, fix_build.reason

    engine = RealLibFuzzerEngine()
    result = await engine.run(
        FuzzRequest(
            task_id="wp4-integration",
            target_id=manifest["case_id"],
            target_path=vuln_build.binary_path or "",
            authorized=True,
            metadata={
                "runs": 50000,
                "max_len": 64,
                "seed": 7,
                "seed_dir": str(CASE_DIR / manifest["seeds_dir"]),
                "work_dir": str(tmp_path / "work"),
                "artifact_dir": str(tmp_path / "artifacts"),
                "fix_binary": fix_build.binary_path,
                "compile_command_hash": vuln_build.compile_command_hash,
                "engine_version": vuln_build.engine_version,
            },
        )
    )

    # The engine really executed and the sanitizer really fired.
    assert result.executed is True
    assert result.crashes == 1
    assert result.metadata["sanitizer_kind"] == "stack-buffer-overflow"

    # 8.4 required fields are all present and linked.
    assert result.metadata["compile_command_hash"]
    assert result.metadata["engine_version"]
    assert result.metadata["corpus_hash"]
    assert result.metadata["crash_input_sha256"]
    assert result.metadata["stack_hash"]
    assert result.metadata["replay_count"] == 1
    assert result.metadata["fixed_outcome"] == "clean"

    # Crash evidence attached with the root-cause facts.
    crash_evidence = [
        item for item in result.evidence if item.evidence_type is EvidenceType.CRASH_LOG
    ]
    assert len(crash_evidence) == 1
    assert (
        crash_evidence[0].data["crash_input_sha256"]
        == result.metadata["crash_input_sha256"]
    )


@pytest.mark.skipif(
    _clang_available(),
    reason="clang available; this test covers the not_run path only",
)
async def test_missing_toolchain_reports_not_run(tmp_path: Path) -> None:
    result = compile_libfuzzer_target(
        CASE_DIR / "vuln.c",
        tmp_path / "out",
        clang=None,
    )
    assert result.compiled is False
    assert "unavailable" in (result.reason or "")
