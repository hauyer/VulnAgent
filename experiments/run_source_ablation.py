"""Run a real source-analysis ablation with verification enabled and disabled.

Every target is self-authored and statically inspected; target code is never
executed. The verification-off arm runs only discovery, while the full arm
uses the canonical bounded runtime through report generation.
"""

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
from vulnagent.agents import SourceAuditAgent, VerificationAgent
from vulnagent.analyzers.source.audit import PythonSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.bootstrap import build_v03_source_application
from vulnagent.contracts import (
    AnalysisContext,
    Target,
    TargetType,
    Task,
    TaskStatus,
    VulnerabilityStatus,
)
from vulnagent.settings import Settings
from vulnagent.verification.evidence_verifier import EvidenceVerifier


LOGGER = logging.getLogger(__name__)
_REQUIRED_SAMPLE_FIELDS = frozenset(
    {
        "sample_id",
        "path",
        "source",
        "language",
        "target_type",
        "ground_truth",
        "cwe",
        "expected_findings",
        "authorization",
        "run_command",
    }
)


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and validate a Python source benchmark manifest."""
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("samples"), list):
        raise ValueError("benchmark manifest must contain a samples list")
    if not manifest["samples"]:
        raise ValueError("benchmark manifest has no samples")

    seen: set[str] = set()
    for index, sample in enumerate(manifest["samples"]):
        if not isinstance(sample, dict):
            raise ValueError(f"sample {index} must be an object")
        missing = sorted(_REQUIRED_SAMPLE_FIELDS.difference(sample))
        if missing:
            raise ValueError(f"sample {index} is missing fields: {', '.join(missing)}")
        sample_id = sample["sample_id"]
        if not isinstance(sample_id, str) or not sample_id:
            raise ValueError(f"sample {index} has an invalid sample_id")
        if sample_id in seen:
            raise ValueError(f"duplicate sample_id: {sample_id}")
        seen.add(sample_id)
        if sample["target_type"] != "source" or sample["language"] != "python":
            raise ValueError(f"sample {sample_id} is not a Python source target")
        if sample["ground_truth"] not in {"vulnerable", "clean"}:
            raise ValueError(f"sample {sample_id} has an invalid ground_truth")
    return manifest


def _resolve_target(repo_root: Path, relative_path: str) -> Path:
    target = (repo_root / relative_path).resolve()
    if not target.is_relative_to(repo_root):
        raise ValueError(f"benchmark target escapes repository root: {relative_path}")
    if not target.exists():
        raise FileNotFoundError(f"benchmark target does not exist: {target}")
    return target


def _evidence_complete(findings: list[Any], evidence: list[Any]) -> bool:
    if not findings:
        return True
    available = {item.evidence_id for item in evidence}
    return all(
        bool(finding.evidence_ids)
        and set(finding.evidence_ids).issubset(available)
        for finding in findings
    )


def _base_row(sample: dict[str, Any], method: str) -> dict[str, Any]:
    return {
        "sample_id": sample["sample_id"],
        "family_id": sample.get("family_id"),
        "difficulty": sample.get("difficulty"),
        "method": method,
        "expected": sample["ground_truth"],
        "expected_findings": sample["expected_findings"],
        "cwe": sample["cwe"],
        "coverage": None,
        "crashes": 0,
        "unique_crashes": 0,
        "token_cost": None,
    }


async def _run_verification_off(
    sample: dict[str, Any],
    target_path: Path,
) -> dict[str, Any]:
    target = Target(
        target_id=str(sample["sample_id"]),
        path=str(target_path),
        target_type=TargetType.SOURCE,
    )
    task = Task(task_id=f"ablation-off-{sample['sample_id']}", target=target)
    agent = SourceAuditAgent(SourceProjectParser(), PythonSourceAuditor())
    started = perf_counter()
    result = await agent.run(task, AnalysisContext(task=task))
    elapsed = perf_counter() - started

    row = _base_row(sample, "vulnagent_verification_off")
    row.update(
        {
            "observed": "vulnerable" if result.findings else "clean",
            "duration_seconds": elapsed,
            "agent_steps": 1,
            "candidate_finding_count": len(result.findings),
            "confirmed_findings": 0,
            "uncertain_findings": 0,
            "rejected_findings": 0,
            "evidence_complete": _evidence_complete(
                result.findings,
                result.evidence,
            ),
            "finding_types": sorted(
                {item.vulnerability_type for item in result.findings}
            ),
        }
    )
    return row


async def _run_verification_on(
    sample: dict[str, Any],
    target_path: Path,
) -> dict[str, Any]:
    """Run discovery plus verification, changing only the tested mechanism."""
    target = Target(
        target_id=str(sample["sample_id"]),
        path=str(target_path),
        target_type=TargetType.SOURCE,
    )
    task = Task(task_id=f"ablation-on-{sample['sample_id']}", target=target)
    started = perf_counter()
    discovery = await SourceAuditAgent(
        SourceProjectParser(),
        PythonSourceAuditor(),
    ).run(task, AnalysisContext(task=task))
    verification = await VerificationAgent(EvidenceVerifier()).run(
        task,
        AnalysisContext(
            task=task,
            messages=discovery.messages,
            findings=discovery.findings,
            evidence=discovery.evidence,
        ),
    )
    elapsed = perf_counter() - started
    evidence = [*discovery.evidence, *verification.evidence]
    confirmed = sum(
        item.status is VulnerabilityStatus.CONFIRMED
        for item in verification.findings
    )
    uncertain = sum(
        item.status is VulnerabilityStatus.UNCERTAIN
        for item in verification.findings
    )
    rejected = sum(
        item.status is VulnerabilityStatus.REJECTED
        for item in verification.findings
    )
    row = _base_row(sample, "vulnagent_verification_on")
    row.update(
        {
            "observed": "vulnerable" if confirmed else "clean",
            "duration_seconds": elapsed,
            "agent_steps": 2,
            "candidate_finding_count": len(verification.findings),
            "confirmed_findings": confirmed,
            "uncertain_findings": uncertain,
            "rejected_findings": rejected,
            "evidence_complete": _evidence_complete(
                verification.findings,
                evidence,
            ),
            "finding_types": sorted(
                {item.vulnerability_type for item in verification.findings}
            ),
            "report_generated": False,
        }
    )
    return row


async def _run_full(
    sample: dict[str, Any],
    target_path: Path,
) -> dict[str, Any]:
    services = build_v03_source_application(
        settings=Settings(vulnagent_profile="v03-source")
    )
    task = services.task_manager.create_task(
        Target(
            target_id=str(sample["sample_id"]),
            path=str(target_path),
            target_type=TargetType.SOURCE,
        )
    )
    started = perf_counter()
    context = await services.orchestrator.run(task.task_id)
    elapsed = perf_counter() - started
    if context.task.status is not TaskStatus.COMPLETED:
        raise RuntimeError(
            f"full runtime failed for {sample['sample_id']}: {context.task.error}"
        )

    confirmed = sum(
        item.status is VulnerabilityStatus.CONFIRMED for item in context.findings
    )
    uncertain = sum(
        item.status is VulnerabilityStatus.UNCERTAIN for item in context.findings
    )
    rejected = sum(
        item.status is VulnerabilityStatus.REJECTED for item in context.findings
    )
    termination = context.task.metadata.get("termination", {})
    row = _base_row(sample, "vulnagent_full")
    row.update(
        {
            "observed": "vulnerable" if confirmed else "clean",
            "duration_seconds": elapsed,
            "agent_steps": termination.get("agent_steps_executed"),
            "candidate_finding_count": len(context.findings),
            "confirmed_findings": confirmed,
            "uncertain_findings": uncertain,
            "rejected_findings": rejected,
            "evidence_complete": _evidence_complete(
                context.findings,
                context.evidence,
            ),
            "finding_types": sorted(
                {item.vulnerability_type for item in context.findings}
            ),
            "report_generated": bool(context.reports),
        }
    )
    return row


async def run_suite(
    manifest_path: Path,
    *,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Run both ablation arms for every manifest sample."""
    manifest = load_manifest(manifest_path)
    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    rows: list[dict[str, Any]] = []
    for sample in manifest["samples"]:
        target_path = _resolve_target(root, str(sample["path"]))
        rows.append(await _run_verification_off(sample, target_path))
        rows.append(await _run_verification_on(sample, target_path))
        rows.append(await _run_full(sample, target_path))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run VulnAgent source verification ablation."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    manifest_path = args.manifest.resolve()
    rows = asyncio.run(run_suite(manifest_path))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "labelled_results.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    metrics = calculate_metrics(rows)
    write_metrics(metrics, args.output_dir)
    provenance = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "suite_id": load_manifest(manifest_path).get("suite_id"),
        "manifest_path": str(manifest_path),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "sample_count": len(rows) // 3,
        "family_count": len(
            {
                str(sample.get("family_id"))
                for sample in load_manifest(manifest_path)["samples"]
                if sample.get("family_id")
            }
        ),
        "difficulty_counts": {
            difficulty: sum(
                sample.get("difficulty") == difficulty
                for sample in load_manifest(manifest_path)["samples"]
            )
            for difficulty in ("basic", "hard")
        },
        "methods": [
            "vulnagent_verification_off",
            "vulnagent_verification_on",
            "vulnagent_full",
        ],
        "profile": "v03-source",
        "python": platform.python_version(),
        "target_execution": False,
    }
    (args.output_dir / "run_manifest.json").write_text(
        json.dumps(provenance, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    LOGGER.info(
        "Completed %d samples; artifacts written to %s",
        len(rows) // 3,
        args.output_dir.resolve(),
    )


if __name__ == "__main__":
    main()
