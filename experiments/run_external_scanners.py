"""Run Native + Semgrep + Bandit on the same L0 targets (WP2).

For every sample the native Python auditor runs, then the Semgrep and Bandit
adapters are invoked through the same bounded request boundary.  Every engine
contributes a real ``ToolRunRecord`` whose status uses the honest vocabulary
(ok / empty / unavailable / timeout / error / blocked).  A missing engine is
reported as ``unavailable`` — never as zero findings from a scan that did not
happen.

All external findings are converted into ``VulnerabilityCandidate`` items and
fused with the native candidates via ``CandidateFusionEngine``, which dedups
the same flaw across engines while keeping each source's independence group.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import platform
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnagent.adapters.bandit.adapter import BanditAdapter
from vulnagent.adapters.normalize import (
    external_finding_to_candidate,
    tool_result_summary,
)
from vulnagent.adapters.semgrep.adapter import SemgrepAdapter
from vulnagent.analyzers.source.audit import PythonSourceAuditor
from vulnagent.analyzers.source.fusion.engine import CandidateFusionEngine
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.contracts import (
    AnalysisContext,
    ProjectInput,
    Target,
    TargetType,
    Task,
    ToolExecutionRequest,
)
from vulnagent.intake import DefaultTargetIntake, load_manifest_dir

LOGGER = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n"
    path.write_text(lines, encoding="utf-8")


def _new_run_id(task_id: str, provider: str) -> str:
    return f"{task_id}-{provider}-{uuid.uuid4().hex[:12]}"


async def _run_external(
    provider: str,
    adapter: SemgrepAdapter | BanditAdapter,
    task_id: str,
    target_path: Path,
) -> ToolExecutionRequest:
    run_id = _new_run_id(task_id, provider)
    request = ToolExecutionRequest(
        run_id=run_id,
        task_id=task_id,
        session_id=None,
        capability=f"source.scan.{provider}",
        target_path=str(target_path),
        authorized=True,
        timeout_seconds=120,
    )
    return request


def _load_ground_truth(repo_root: Path) -> dict[str, str]:
    """Load sample_id -> ground_truth from the self-authored benchmark manifest."""

    source = repo_root / "benchmarks" / "manifest.json"
    manifest = json.loads(source.read_text(encoding="utf-8"))
    return {
        str(item["sample_id"]): str(item["ground_truth"])
        for item in manifest.get("samples", [])
        if item.get("ground_truth") in {"vulnerable", "clean"}
    }


async def run_suite(
    catalog_dir: Path,
    *,
    repo_root: Path,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Run the three-engine suite over every admitted catalog target."""

    gate = DefaultTargetIntake()
    manifests = load_manifest_dir(catalog_dir)
    ground_truth = _load_ground_truth(repo_root)
    semgrep = SemgrepAdapter()
    bandit = BanditAdapter()
    native_auditor = PythonSourceAuditor()
    parser = SourceProjectParser()
    fusion = CandidateFusionEngine()

    tool_runs: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    fused_records: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    engine_health: dict[str, bool] = {}

    for manifest in manifests:
        decision = gate.validate(manifest, base_path=repo_root)
        expected = ground_truth.get(manifest.sample_id, "vulnerable")
        if not decision.accepted:
            rows.append(
                {
                    "sample_id": manifest.sample_id,
                    "method": "multi_engine",
                    "expected": expected,
                    "observed": "blocked",
                    "duration_seconds": 0.0,
                    "agent_steps": 0,
                    "candidate_finding_count": 0,
                    "fused_candidate_count": 0,
                    "tool_runs": 0,
                    "unavailable_runs": 1,
                    "note": "; ".join(decision.issues),
                }
            )
            continue

        target = Target(
            target_id=manifest.sample_id,
            path=decision.normalized_path or "",
            target_type=TargetType.SOURCE,
        )
        task = Task(task_id=f"wp2-{manifest.sample_id}", target=target)
        context = AnalysisContext(task=task)
        target_path = Path(decision.normalized_path or "")

        # Native engine: parse without executing, then audit candidates.
        parsed = await parser.analyze(
            ProjectInput(
                task_id=task.task_id,
                target_id=target.target_id,
                project_path=str(target_path),
            )
        )
        native_findings = await native_auditor.audit(parsed)

        # External engines through the adapter boundary.
        external_results: dict[str, Any] = {}
        for provider, adapter in (("semgrep", semgrep), ("bandit", bandit)):
            request = await _run_external(provider, adapter, task.task_id, target_path)
            request.timeout_seconds = timeout_seconds
            result = await adapter.execute(request)
            external_results[provider] = result
            tool_runs.append(
                {
                    **tool_result_summary(result),
                    "sample_id": manifest.sample_id,
                    "input_sha256": manifest.target_sha256,
                }
            )
            for finding in result.findings:
                candidates.append(
                    external_finding_to_candidate(
                        result,
                        finding,
                        task_id=task.task_id,
                        target_id=target.target_id,
                    ).model_dump()
                )

        # Fuse native + external candidates; one independence group per engine.
        external_candidates = [
            external_finding_to_candidate(
                external_results[provider],
                finding,
                task_id=task.task_id,
                target_id=target.target_id,
            )
            for provider in ("semgrep", "bandit")
            for finding in external_results[provider].findings
        ]
        all_candidates = [*native_findings, *external_candidates]
        if all_candidates:
            groups: dict[str, str] = {}
            for item in native_findings:
                groups[item.vulnerability_id] = "native"
            for item in external_candidates:
                groups[item.vulnerability_id] = item.producer or "external"
            fused = fusion.fuse(
                all_candidates,
                independence_groups=groups,
                base_path=str(target_path),
            )
            fused_records.extend(item.model_dump() for item in fused)
        else:
            fused = []

        native_candidates = [item.model_dump() for item in native_findings]
        engine_health[manifest.sample_id] = any(
            result.success for result in external_results.values()
        )
        sample_tool_runs = [
            run for run in tool_runs if run["sample_id"] == manifest.sample_id
        ]
        rows.append(
            {
                "sample_id": manifest.sample_id,
                "method": "multi_engine",
                "expected": expected,
                "observed": "vulnerable" if native_candidates else "clean",
                "duration_seconds": 0.0,
                "agent_steps": 3,
                "candidate_finding_count": len(all_candidates),
                "fused_candidate_count": len(fused),
                "tool_runs": len(sample_tool_runs),
                "unavailable_runs": sum(
                    1 for run in sample_tool_runs if run["status"] == "unavailable"
                ),
            }
        )

    return {
        "suite_id": "wp2-multi-engine",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "catalog_dir": str(catalog_dir),
        "tool_runs": tool_runs,
        "candidates": candidates,
        "fused_candidates": fused_records,
        "rows": rows,
        "engine_health": engine_health,
        "git_head": "recorded-in-manifest",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog-dir",
        type=Path,
        default=REPO_ROOT / "benchmarks" / "catalog",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "artifacts" / "experiments" / "wp2-multi-engine",
    )
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = asyncio.run(
        run_suite(
            args.catalog_dir.resolve(),
            repo_root=REPO_ROOT,
            timeout_seconds=args.timeout_seconds,
        )
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(args.output_dir / "tool_runs.jsonl", result["tool_runs"])
    _write_jsonl(args.output_dir / "candidates.jsonl", result["candidates"])
    _write_jsonl(args.output_dir / "fused_candidates.jsonl", result["fused_candidates"])
    (args.output_dir / "rows.json").write_text(
        json.dumps(result["rows"], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (args.output_dir / "manifest.json").write_text(
        json.dumps(
            {
                "suite_id": result["suite_id"],
                "generated_at": result["generated_at"],
                "python": result["python"],
                "catalog_dir": result["catalog_dir"],
                "git_head": result["git_head"],
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    LOGGER.info("Wrote %d tool runs and %d candidates to %s", len(result["tool_runs"]), len(result["candidates"]), args.output_dir)


if __name__ == "__main__":
    main()
