"""Compare fixed-budget generic fuzzing with static-risk-guided fuzzing."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import platform
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from experiments.run_metrics import calculate_metrics, write_metrics
from experiments.run_source_ablation import load_manifest
from vulnagent.agents import FuzzAgent, SourceAuditAgent
from vulnagent.analyzers.source.audit import PythonSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.contracts import (
    AnalysisContext,
    EvidenceType,
    FuzzRequest,
    Target,
    TargetType,
    Task,
)
from vulnagent.fuzz.engine import ControlledFuzzEngine


LOGGER = logging.getLogger(__name__)


def _resolve_target(repo_root: Path, relative_path: str) -> Path:
    target = (repo_root / relative_path).resolve()
    if not target.is_relative_to(repo_root):
        raise ValueError(f"benchmark target escapes repository root: {relative_path}")
    if not target.is_file():
        raise FileNotFoundError(f"fuzz benchmark target is not a file: {target}")
    return target


async def _discover(task: Task) -> AnalysisContext:
    result = await SourceAuditAgent(
        SourceProjectParser(),
        PythonSourceAuditor(),
    ).run(task, AnalysisContext(task=task))
    if not result.findings:
        raise RuntimeError("guided fuzz benchmark requires a real static candidate")
    return AnalysisContext(
        task=task,
        messages=result.messages,
        findings=result.findings,
        evidence=result.evidence,
    )


def _row(
    *,
    method: str,
    trial: int,
    elapsed: float,
    crashes: int,
    coverage: float | None,
    metadata: dict[str, Any],
    evidence_complete: bool,
    agent_steps: int,
) -> dict[str, Any]:
    return {
        "sample_id": f"py-fuzz-guidance-001-trial-{trial:03d}",
        "trial": trial,
        "method": method,
        "expected": "vulnerable",
        "observed": "vulnerable" if crashes else "clean",
        "duration_seconds": elapsed,
        "agent_steps": agent_steps,
        "token_cost": None,
        "coverage": coverage,
        "crashes": crashes,
        "unique_crashes": len(metadata.get("crash_fingerprints", [])),
        "crash_fingerprints": metadata.get("crash_fingerprints", []),
        "confirmed_findings": 0,
        "uncertain_findings": 0,
        "evidence_complete": evidence_complete,
        "attempts": metadata.get("attempts", 0),
        "guided_mutations": metadata.get("guided_mutations", 0),
        "generic_mutations": metadata.get("generic_mutations", 0),
        "mutation_strategy": metadata.get("mutation_strategy"),
        "guidance_risk_types": metadata.get("guidance_risk_types", []),
        "sandbox_profiles": metadata.get("sandbox_profiles", []),
    }


def _collect_sandbox_profiles(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return one stable, non-secret capability record per sandbox backend."""

    profiles: dict[str, dict[str, Any]] = {}
    for row in rows:
        for raw_profile in row.get("sandbox_profiles", []):
            if not isinstance(raw_profile, dict):
                continue
            backend_name = raw_profile.get("backend_name")
            if isinstance(backend_name, str) and backend_name:
                profiles[backend_name] = dict(raw_profile)
    return [profiles[name] for name in sorted(profiles)]


async def run_suite(
    manifest_path: Path,
    *,
    repo_root: Path | None = None,
    trials: int = 10,
    mutation_count: int = 8,
) -> list[dict[str, Any]]:
    """Run both methods with identical targets, seeds and execution budgets."""
    if trials <= 0 or mutation_count <= 0:
        raise ValueError("trials and mutation_count must be positive")
    manifest = load_manifest(manifest_path)
    if len(manifest["samples"]) != 1:
        raise ValueError("fuzz guidance MVP manifest must contain exactly one sample")
    sample = manifest["samples"][0]
    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    target_path = _resolve_target(root, str(sample["path"]))
    seed_dir = target_path.parent / "seeds"
    if not seed_dir.is_dir():
        raise FileNotFoundError(f"seed directory does not exist: {seed_dir}")

    task = Task(
        task_id="fuzz-ablation-discovery",
        target=Target(
            target_id=str(sample["sample_id"]),
            path=str(target_path),
            target_type=TargetType.SOURCE,
            language="python",
            metadata={
                "fuzz_authorized": True,
                "dynamic_validation": True,
                "seed_dir": str(seed_dir),
            },
        ),
    )
    discovery_context = await _discover(task)
    rows: list[dict[str, Any]] = []
    for trial in range(trials):
        generic_engine = ControlledFuzzEngine(
            mutation_count=mutation_count,
            seed=trial,
        )
        started = perf_counter()
        generic = await generic_engine.run(
            FuzzRequest(
                task_id=f"fuzz-generic-{trial}",
                target_id=task.target.target_id,
                target_path=str(target_path),
                authorized=True,
                metadata={"seed_dir": str(seed_dir)},
            )
        )
        elapsed = perf_counter() - started
        rows.append(
            _row(
                method="traditional_random_fuzz",
                trial=trial,
                elapsed=elapsed,
                crashes=generic.crashes,
                coverage=generic.coverage,
                metadata=generic.metadata,
                evidence_complete=bool(generic.evidence),
                agent_steps=1,
            )
        )

        guided_engine = ControlledFuzzEngine(
            mutation_count=mutation_count,
            seed=trial,
        )
        started = perf_counter()
        guided_result = await FuzzAgent(guided_engine).run(
            task,
            discovery_context,
        )
        elapsed = perf_counter() - started
        payload = guided_result.messages[-1].payload
        crash_evidence = [
            item
            for item in guided_result.evidence
            if item.evidence_type is EvidenceType.CRASH_LOG
        ]
        evidence_ids = {item.evidence_id for item in guided_result.evidence}
        evidence_complete = bool(guided_result.evidence) and all(
            set(finding.evidence_ids).issubset(evidence_ids)
            for finding in guided_result.findings
        )
        rows.append(
            _row(
                method="agent_guided_fuzz",
                trial=trial,
                elapsed=elapsed,
                crashes=int(payload.get("crashes", len(crash_evidence))),
                coverage=payload.get("coverage"),
                metadata=dict(payload.get("metadata", {})),
                evidence_complete=evidence_complete,
                agent_steps=2,
            )
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--mutation-count", type=int, default=8)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    manifest_path = args.manifest.resolve()
    rows = asyncio.run(
        run_suite(
            manifest_path,
            trials=args.trials,
            mutation_count=args.mutation_count,
        )
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "labelled_results.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    write_metrics(calculate_metrics(rows), args.output_dir)
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifest_path": str(manifest_path),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "python": platform.python_version(),
        "trials": args.trials,
        "mutation_count_per_trial": args.mutation_count,
        "methods": ["traditional_random_fuzz", "agent_guided_fuzz"],
        "authorization": "self-authored local target only",
        "network_policy": "declared_disabled_not_os_enforced",
        "payload_policy": "inert_markers_and_parser_boundaries",
        "sandbox_profiles": _collect_sandbox_profiles(rows),
    }
    (args.output_dir / "run_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    LOGGER.info("Completed %d paired trials in %s", args.trials, args.output_dir)


if __name__ == "__main__":
    main()
