"""WP4 real libFuzzer/ASan closed loop on an authorized local C case.

Pipeline:
  1. load the case manifest (vuln + fix sources, seeds, expected facts)
  2. compile the vulnerable and fixed targets with clang-cl + ASan + libFuzzer
     (a missing toolchain is recorded as ``not_run`` with the reason)
  3. run the real libFuzzer engine through the sandbox with a fixed budget
  4. collect the crash artifact, replay it independently, and contrast the
     same input against the fixed build
  5. write run_manifest.json, tool_runs.jsonl, candidates.jsonl,
     evidence.jsonl and metrics.json (all reproducible)

Usage (from the repo root):
  python -m experiments.run_real_libfuzzer
  python -m experiments.run_real_libfuzzer --runs 30000 --max-len 64 --seed 7
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from vulnagent.contracts import (
    FuzzRequest,
    Target,
    TargetType,
    Task,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)
from vulnagent.fuzz.libfuzzer import RealLibFuzzerEngine
from vulnagent.sandbox.compiler import (
    clang_version,
    compile_libfuzzer_target,
    locate_clang,
)
from vulnagent.utils.ids import new_vulnerability_id

LOGGER = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = "\n".join(
        json.dumps(record, ensure_ascii=False) for record in records
    ) + "\n"
    path.write_text(lines, encoding="utf-8")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def _run_case(
    case_dir: Path,
    output_dir: Path,
    *,
    runs: int,
    max_len: int,
    max_total_time: int,
    seed: int,
) -> dict[str, Any]:
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8"))
    compile_spec = manifest["compile"]
    case_id = manifest["case_id"]

    build_dir = output_dir / "build"
    artifacts_dir = output_dir / "artifacts"
    work_dir = output_dir / "work"

    clang = locate_clang()
    toolchain_note = (
        {"clang": str(clang), "engine_version": clang_version(clang)}
        if clang is not None
        else {"reason": "clang unavailable; set VULNAGENT_CLANG or install LLVM"}
    )

    vuln_source = case_dir / compile_spec["vuln_source"]
    fix_source = case_dir / compile_spec["fix_source"]

    vuln_build = compile_libfuzzer_target(
        vuln_source,
        build_dir / "vuln",
        clang=clang,
        sanitizer="address",
        opt_level=compile_spec["flags"][0],
    )
    fix_build = compile_libfuzzer_target(
        fix_source,
        build_dir / "fix",
        clang=clang,
        sanitizer="address",
        opt_level=compile_spec["flags"][0],
    )

    if not vuln_build.compiled:
        result = {
            "case_id": case_id,
            "executed": False,
            "status": "not_run",
            "reason": vuln_build.reason or "vuln build failed",
            "compile_command_hash": vuln_build.compile_command_hash,
            "engine_version": vuln_build.engine_version,
            "toolchain": toolchain_note,
            "stderr": vuln_build.stderr[:2048],
        }
        _write_json(output_dir / "run_manifest.json", _manifest(manifest, result))
        return result

    task = Task(
        task_id=f"wp4-{case_id}-{seed}",
        target=Target(
            target_id=case_id,
            path=vuln_build.binary_path or "",
            target_type=TargetType.BINARY,
            metadata={"fuzz_authorized": True, "case_id": case_id},
        ),
    )
    engine = RealLibFuzzerEngine()
    fuzz_result = await engine.run(
        FuzzRequest(
            task_id=task.task_id,
            target_id=case_id,
            target_path=vuln_build.binary_path or "",
            authorized=True,
            metadata={
                "runs": runs,
                "max_len": max_len,
                "max_total_time": max_total_time,
                "seed": seed,
                "seed_dir": str(case_dir / manifest["seeds_dir"]),
                "work_dir": str(work_dir),
                "artifact_dir": str(artifacts_dir),
                "fix_binary": fix_build.binary_path,
                "compile_command_hash": vuln_build.compile_command_hash,
                "engine_version": vuln_build.engine_version,
            },
        )
    )

    candidates: list[dict[str, Any]] = []
    if fuzz_result.crashes > 0:
        crash_meta = fuzz_result.metadata
        candidate = VulnerabilityCandidate(
            vulnerability_id=new_vulnerability_id(),
            task_id=task.task_id,
            title="Real libFuzzer/ASan crash requires independent verification",
            vulnerability_type="stack_buffer_overflow",
            cwe_id=manifest.get("cwe_id"),
            description=(
                f"Authorized local libFuzzer run reported "
                f"{crash_meta.get('sanitizer_kind')} "
                f"({crash_meta.get('crash_signature')}) with a reproducible "
                "crash input; replay and fixed-version contrast are attached."
            ),
            target_id=case_id,
            location=VulnerabilityLocation(
                module_name=case_id,
                function="parse_message",
            ),
            source_agent="fuzz",
            source_type="dynamic",
            producer="RealLibFuzzerEngine",
            confidence=0.92,
            severity="HIGH",
            evidence_ids=[item.evidence_id for item in fuzz_result.evidence],
            metadata={
                "mock": False,
                "authorized": True,
                "engine": "libfuzzer",
                "sanitizer_kind": crash_meta.get("sanitizer_kind"),
                "crash_signature": crash_meta.get("crash_signature"),
                "stack_hash": crash_meta.get("stack_hash"),
                "crash_input_sha256": crash_meta.get("crash_input_sha256"),
                "fixed_outcome": crash_meta.get("fixed_outcome"),
                "replay_count": crash_meta.get("replay_count"),
                "runs": crash_meta.get("runs"),
                "coverage": crash_meta.get("coverage"),
            },
        )
        candidates.append(candidate.model_dump(mode="json"))

    tool_runs = [
        {
            "run_id": f"wp4-{case_id}-{seed}-libfuzzer",
            "task_id": task.task_id,
            "engine": "libfuzzer",
            "status": "ok" if fuzz_result.executed else "error",
            "metadata": dict(fuzz_result.metadata),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    ]

    evidence = [item.model_dump(mode="json") for item in fuzz_result.evidence]

    metrics = {
        "case_id": case_id,
        "executed": fuzz_result.executed,
        "crashes": fuzz_result.crashes,
        "runs": fuzz_result.metadata.get("runs"),
        "coverage": fuzz_result.coverage,
        "crash_input_sha256": fuzz_result.metadata.get("crash_input_sha256"),
        "fixed_outcome": fuzz_result.metadata.get("fixed_outcome"),
        "replay_count": fuzz_result.metadata.get("replay_count"),
        "stack_hash": fuzz_result.metadata.get("stack_hash"),
        "sanitizer_kind": fuzz_result.metadata.get("sanitizer_kind"),
    }

    result = {
        "case_id": case_id,
        "executed": fuzz_result.executed,
        "status": "ok" if fuzz_result.executed else "error",
        "crashes": fuzz_result.crashes,
        "toolchain": toolchain_note,
        "compile_command_hash": vuln_build.compile_command_hash,
        "engine_version": vuln_build.engine_version,
        "fix_build_compiled": fix_build.compiled,
        "metrics": metrics,
    }
    _write_json(
        output_dir / "run_manifest.json",
        _manifest(manifest, result),
    )
    _write_jsonl(output_dir / "tool_runs.jsonl", tool_runs)
    _write_jsonl(output_dir / "candidates.jsonl", candidates)
    _write_jsonl(output_dir / "evidence.jsonl", evidence)
    _write_json(output_dir / "metrics.json", metrics)
    return result


def _manifest(manifest: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return {
        "case": manifest.get("case_id"),
        "cwe_id": manifest.get("cwe_id"),
        "expected": manifest.get("expected"),
        "repo_commit": "local",
        "platform": platform.system(),
        "python": sys.version.split()[0],
        "result": result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--case-dir",
        type=Path,
        default=REPO_ROOT / "benchmarks" / "dynamic" / "libfuzzer" / "cp_parse",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "artifacts" / "experiments" / "wp4-libfuzzer",
    )
    parser.add_argument("--runs", type=int, default=20000)
    parser.add_argument("--max-len", type=int, default=64)
    parser.add_argument("--max-total-time", type=int, default=90)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    result = await _run_case(
        args.case_dir,
        args.output_dir,
        runs=args.runs,
        max_len=args.max_len,
        max_total_time=args.max_total_time,
        seed=args.seed,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
