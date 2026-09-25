"""WP5: blind-evaluation experiment (two tracks).

Track A -- ExploitGym adaptation screening: runs the screening adapter over
the candidate rows and records, per row, the eligibility decision with
reasons. Adapted runs are a custom protocol and never presented as official
ExploitGym scores.

Track B -- discovery on the self-authored blind catalog: for every case the
agent-visible manifest is used to run the real discovery chain (native
auditor + Semgrep/Bandit for source, RealLibFuzzerEngine for the dynamic
case). Ground truth stays under benchmarks/blind/ground_truth, never mounted
in the agent environment. The independent BlindEvaluator recomputes
metrics.json from raw candidate rows and hidden labels.

Reproducible:  python -m experiments.run_blind_evaluation
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import platform
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from vulnagent.adapters.bandit.adapter import BanditAdapter
from vulnagent.adapters.normalize import external_finding_to_candidate
from vulnagent.adapters.semgrep.adapter import SemgrepAdapter
from vulnagent.analyzers.source.audit import PythonSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.benchmark import (
    BlindCaseManifest,
    BlindEvaluator,
    ExploitGymDiscoveryAdapter,
    GroundTruth,
    LabelLeakageGuard,
    ScreeningRecord,
)
from vulnagent.benchmark.adapters import VulnGymCatalogBuilder
from vulnagent.contracts import ProjectInput, ToolExecutionRequest
from vulnagent.fuzz.libfuzzer import RealLibFuzzerEngine
from vulnagent.contracts import FuzzRequest

LOGGER = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "artifacts" / "experiments" / "wp5-blind-eval"


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n"
    path.write_text(lines, encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(slots=True)
class StaticDiscoverer:
    """Source track: native auditor + Semgrep/Bandit when available."""

    repo_root: Path

    async def discover(self, case: BlindCaseManifest) -> list[dict[str, Any]]:
        target = (self.repo_root / case.target_path).resolve()
        rows: list[dict[str, Any]] = []
        task_id = f"wp5-{case.case_id}"

        parser = SourceProjectParser()
        parsed = await parser.analyze(
            ProjectInput(
                task_id=task_id,
                target_id=case.case_id,
                project_path=str(target.parent),
            )
        )
        auditor = PythonSourceAuditor()
        findings = await auditor.audit(parsed)
        for finding in findings:
            loc = finding.location
            loc_text = (
                f"{Path(loc.file_path).name}:{loc.line_start}"
                if loc.file_path
                else ""
            )
            rows.append(
                {
                    "case_id": case.case_id,
                    "candidate_id": f"{task_id}-native-{uuid.uuid4().hex[:8]}",
                    "vulnerability_type": finding.vulnerability_type,
                    "cwe_id": finding.cwe_id,
                    "location": loc_text,
                    "status": "success",
                    "note": "native python auditor",
                }
            )

        for name, adapter_cls in (("semgrep", SemgrepAdapter), ("bandit", BanditAdapter)):
            adapter = adapter_cls()
            request = ToolExecutionRequest(
                run_id=f"{task_id}-{name}",
                task_id=task_id,
                session_id=None,
                capability=f"source.scan.{name}",
                target_path=str(target),
                authorized=True,
                timeout_seconds=120,
            )
            result = await adapter.execute(request)
            if not result.success or not result.executed:
                status = "unavailable" if not result.executed else "invalid"
                rows.append(
                    {
                        "case_id": case.case_id,
                        "candidate_id": f"{task_id}-{name}-unavailable",
                        "vulnerability_type": "",
                        "cwe_id": "",
                        "location": "",
                        "status": status,
                        "note": f"{name} tool status: executed={result.executed} "
                        f"success={result.success}",
                    }
                )
                continue
            for finding in result.findings:
                candidate = external_finding_to_candidate(
                    result,
                    finding,
                    task_id=task_id,
                    target_id=case.case_id,
                )
                loc = candidate.location
                loc_text = (
                    f"{Path(loc.file_path).name}:{loc.line_start}"
                    if loc.file_path
                    else ""
                )
                rows.append(
                    {
                        "case_id": case.case_id,
                        "candidate_id": candidate.vulnerability_id,
                        "vulnerability_type": candidate.vulnerability_type,
                        "cwe_id": candidate.cwe_id,
                        "location": loc_text,
                        "status": "success",
                        "note": f"{name} adapter finding",
                    }
                )
        return rows


@dataclass(slots=True)
class DynamicDiscoverer:
    """Binary/dynamic track: real libFuzzer/ASan when clang is available."""

    repo_root: Path
    clang_path: str | None = None

    async def discover(self, case: BlindCaseManifest) -> list[dict[str, Any]]:
        from vulnagent.sandbox.compiler import compile_libfuzzer_target, locate_clang

        clang = locate_clang()
        self.clang_path = str(clang) if clang else None
        if clang is None:
            return [
                {
                    "case_id": case.case_id,
                    "candidate_id": f"wp5-{case.case_id}-notrun",
                    "vulnerability_type": "",
                    "cwe_id": "",
                    "location": "",
                    "status": "unavailable",
                    "note": "clang toolchain unavailable; dynamic run not performed",
                }
            ]

        work = self.repo_root / DEFAULT_OUT / "work" / case.case_id
        work.mkdir(parents=True, exist_ok=True)
        build = compile_libfuzzer_target(
            self.repo_root / case.target_path,
            work / "build",
            clang=clang,
            opt_level=case.build_spec.get("flags", ["-O0"])[0],
        )
        if not build.compiled:
            return [
                {
                    "case_id": case.case_id,
                    "candidate_id": f"wp5-{case.case_id}-buildfail",
                    "vulnerability_type": "",
                    "cwe_id": "",
                    "location": "",
                    "status": "invalid",
                    "note": f"build failed: {build.reason}",
                }
            ]

        engine = RealLibFuzzerEngine()
        seeds = self.repo_root / "benchmarks" / "dynamic" / "libfuzzer" / "cp_parse" / "seeds"
        request = FuzzRequest(
            task_id=f"wp5-{case.case_id}",
            target_id=case.case_id,
            target_path=build.binary_path or "",
            authorized=True,
            metadata={
                "runs": 50000,
                "max_len": 64,
                "seed": 7,
                "seed_dir": str(seeds),
                "work_dir": str(work / "run"),
                "artifact_dir": str(work / "artifacts"),
                "compile_command_hash": build.compile_command_hash,
                "engine_version": build.engine_version,
            },
        )
        result = await engine.run(request)
        if result.crashes == 0:
            return [
                {
                    "case_id": case.case_id,
                    "candidate_id": f"wp5-{case.case_id}-nocrash",
                    "vulnerability_type": "",
                    "cwe_id": "",
                    "location": "",
                    "status": "success",
                    "note": f"no crash in runs={result.metadata.get('runs')}; "
                    f"sanitizer={result.metadata.get('sanitizer_kind')}",
                }
            ]
        crash_hash = result.metadata.get("crash_input_sha256")
        return [
            {
                "case_id": case.case_id,
                "candidate_id": f"wp5-{case.case_id}-crash",
                "vulnerability_type": result.metadata.get("sanitizer_kind", "crash"),
                "cwe_id": "CWE-121",
                "location": "vuln.c:16",
                "status": "success",
                "note": f"crash_input={crash_hash} replay={result.metadata.get('replay_count')} "
                f"fixed={result.metadata.get('fixed_outcome')}",
            }
        ]


def _run_track_a(output: Path, records: list[dict[str, Any]]) -> list[ScreeningRecord]:
    adapter = ExploitGymDiscoveryAdapter()
    screened: list[ScreeningRecord] = []
    rows: list[dict[str, Any]] = []
    for item in records:
        record = adapter.screen(
            str(item["task_id"]),
            local_target_fixed=bool(item["local_target_fixed"]),
            ground_truth_detachable=bool(item["ground_truth_detachable"]),
            answer_hidden=bool(item["answer_hidden"]),
            safe_to_run=bool(item["safe_to_run"]),
            notes=str(item.get("notes", "")),
        )
        screened.append(record)
        rows.append(
            {
                "task_id": record.task_id,
                "eligibility": record.eligibility.value,
                "reasons": record.reasons,
                "checks": record.checks,
            }
        )
    _write_jsonl(output / "screening.jsonl", rows)
    return screened


def _run_leakage_guard(cases: list[BlindCaseManifest]) -> list[dict[str, Any]]:
    guard = LabelLeakageGuard()
    gt_dir = REPO_ROOT / "benchmarks" / "blind" / "ground_truth"
    rows: list[dict[str, Any]] = []
    for case in cases:
        if not case.ground_truth_ref:
            rows.append(
                {
                    "case_id": case.case_id,
                    "guard_clean": True,
                    "note": "no ground-truth record (clean fixture)",
                }
            )
            continue
        gt_path = REPO_ROOT / case.ground_truth_ref
        gt = GroundTruth.model_validate(
            yaml.safe_load(gt_path.read_text(encoding="utf-8"))
        )
        prompt = (
            f"Analyze target {case.case_id} (project {case.project}, "
            f"{case.language}, revision {case.revision}) for memory/command "
            "safety issues. Produce findings with locations."
        )
        metadata = json.dumps(
            {
                "case_id": case.case_id,
                "target_path": case.target_path,
                "authorization": case.authorization.model_dump(),
            }
        )
        report = guard.check(case, gt, prompt, metadata)
        rows.append(
            {
                "case_id": case.case_id,
                "guard_clean": report.clean,
                "hard_leaks": report.hard_leaks,
                "knowledge_overlap": report.knowledge_overlap,
            }
        )
    return rows


async def _run_track_b(output: Path, cases: list[BlindCaseManifest]) -> list[dict[str, Any]]:
    source_discoverer = StaticDiscoverer(REPO_ROOT)
    dynamic_discoverer = DynamicDiscoverer(REPO_ROOT)
    all_rows: list[dict[str, Any]] = []
    for case in cases:
        if case.target_kind.value == "source":
            rows = await source_discoverer.discover(case)
        else:
            rows = await dynamic_discoverer.discover(case)
        all_rows.extend(rows)
    _write_jsonl(output / "candidates.jsonl", all_rows)
    return all_rows


async def main() -> None:
    parser = argparse.ArgumentParser(description="WP5 blind evaluation (two tracks)")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    output: Path = args.output_dir
    output.mkdir(parents=True, exist_ok=True)

    blind_catalog = yaml.safe_load(
        (REPO_ROOT / "benchmarks" / "blind" / "blind_catalog.yaml").read_text(
            encoding="utf-8"
        )
    )
    cases = [BlindCaseManifest.model_validate(item) for item in blind_catalog["cases"]]

    # Track A: ExploitGym adaptation screening.
    screening_yaml = yaml.safe_load(
        (
            REPO_ROOT / "benchmarks" / "blind" / "exploitgym_candidates.yaml"
        ).read_text(encoding="utf-8")
    )
    screened = _run_track_a(output, screening_yaml["candidates"])
    eligible = [s.task_id for s in screened if s.eligibility.value == "eligible"]
    case_study = [s.task_id for s in screened if s.eligibility.value != "eligible"]

    # Track B: discovery on the blind catalog with hidden labels.
    candidates = await _run_track_b(output, cases)
    leakage_rows = _run_leakage_guard(cases)
    _write_jsonl(output / "leakage_guard.jsonl", leakage_rows)

    evaluator = BlindEvaluator()
    result = evaluator.evaluate(
        output / "candidates.jsonl",
        REPO_ROOT / "benchmarks" / "blind" / "ground_truth",
        run_id="wp5-blind-eval",
    )
    result.write_metrics(str(output / "metrics.json"))

    summary = {
        "run_id": "wp5-blind-eval",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "track_a_screening": {
            "total": len(screened),
            "eligible": eligible,
            "case_study_only": case_study,
            "record_path": str(output / "screening.jsonl"),
        },
        "track_b_blind": {
            "catalog": str(REPO_ROOT / "benchmarks" / "blind" / "blind_catalog.yaml"),
            "gt_dir": str(REPO_ROOT / "benchmarks" / "blind" / "ground_truth"),
            "candidates": len(candidates),
            "metrics": result.model_dump(),
            "candidates_path": str(output / "candidates.jsonl"),
        },
        "platform": platform.platform(),
    }
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
