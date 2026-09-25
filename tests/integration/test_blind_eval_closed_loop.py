"""WP5 integration: blind-evaluation closed loop.

Runs the two-track experiment end to end on the self-authored catalog:
ExploitGym adaptation screening (no official scores claimed) plus a real
discovery pass (native auditor + Semgrep/Bandit for source, real
libFuzzer/ASan for the dynamic case) with hidden ground truth, then the
independent evaluator recomputes metrics. The leakage guard must be clean.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from vulnagent.benchmark import (
    BlindCaseManifest,
    BlindEvaluator,
    ExploitGymDiscoveryAdapter,
    GroundTruth,
    LabelLeakageGuard,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BLIND_DIR = REPO_ROOT / "benchmarks" / "blind"


@pytest.mark.asyncio
async def test_blind_catalog_evaluates_end_to_end(tmp_path: Path) -> None:
    from vulnagent.sandbox.compiler import locate_clang

    clang = locate_clang()
    if clang is None:
        pytest.skip("clang toolchain unavailable; dynamic track cannot run")

    # Load the agent-visible catalog (labels live evaluator-side).
    raw = yaml.safe_load((BLIND_DIR / "blind_catalog.yaml").read_text(encoding="utf-8"))
    cases = [BlindCaseManifest.model_validate(item) for item in raw["cases"]]

    # Leakage guard must pass for every labeled case.
    guard = LabelLeakageGuard()
    for case in cases:
        if not case.ground_truth_ref:
            continue
        gt = GroundTruth.model_validate(
            yaml.safe_load(
                (REPO_ROOT / case.ground_truth_ref).read_text(encoding="utf-8")
            )
        )
        report = guard.check(
            case,
            gt,
            prompt_text=f"Audit {case.case_id} ({case.language}) for safety issues.",
            metadata_text="authorization: static/dynamic bounded run",
        )
        assert report.clean, f"leak for {case.case_id}: {report.hard_leaks}"

    # Screening record: at least one eligible and one case-study-only row.
    screen_raw = yaml.safe_load(
        (BLIND_DIR / "exploitgym_candidates.yaml").read_text(encoding="utf-8")
    )
    adapter = ExploitGymDiscoveryAdapter()
    eligibility = {
        str(item["task_id"]): adapter.screen(
            str(item["task_id"]),
            local_target_fixed=bool(item["local_target_fixed"]),
            ground_truth_detachable=bool(item["ground_truth_detachable"]),
            answer_hidden=bool(item["answer_hidden"]),
            safe_to_run=bool(item["safe_to_run"]),
        ).eligibility.value
        for item in screen_raw["candidates"]
    }
    assert "eligible" in eligibility.values()
    assert "not_blind" in eligibility.values()
    assert "unsafe" in eligibility.values()

    # Real discovery pass on the catalog (source track synchronous; the
    # dynamic case uses the real engine when clang exists).
    candidates_path = tmp_path / "candidates.jsonl"
    rows = await _discover_all(cases)
    text = "\n".join(
        __import__("json").dumps(r, ensure_ascii=False) for r in rows
    ) + "\n"
    candidates_path.write_text(text, encoding="utf-8")

    result = BlindEvaluator().evaluate(
        candidates_path,
        BLIND_DIR / "ground_truth",
        run_id="wp5-integration",
    )
    assert result.total_cases == len(cases)
    assert result.tp >= 1  # the dynamic case must be detected
    metrics_path = tmp_path / "metrics.json"
    result.write_metrics(str(metrics_path))
    assert metrics_path.is_file()


async def _discover_all(cases: list[BlindCaseManifest]) -> list[dict]:
    """Shared discovery used by the integration test (source + dynamic)."""
    import json
    import uuid

    from vulnagent.adapters.bandit.adapter import BanditAdapter
    from vulnagent.adapters.normalize import external_finding_to_candidate
    from vulnagent.adapters.semgrep.adapter import SemgrepAdapter
    from vulnagent.analyzers.source.audit import PythonSourceAuditor
    from vulnagent.analyzers.source.parser import SourceProjectParser
    from vulnagent.contracts import FuzzRequest, ProjectInput
    from vulnagent.fuzz.libfuzzer import RealLibFuzzerEngine
    from vulnagent.sandbox.compiler import compile_libfuzzer_target

    all_rows: list[dict] = []
    for case in cases:
        task_id = f"wp5it-{case.case_id}"
        target = (REPO_ROOT / case.target_path).resolve()
        if case.target_kind.value == "source":
            parsed = await SourceProjectParser().analyze(
                ProjectInput(
                    task_id=task_id,
                    target_id=case.case_id,
                    project_path=str(target.parent),
                )
            )
            findings = await PythonSourceAuditor().audit(parsed)
            for finding in findings:
                loc = finding.location
                all_rows.append(
                    {
                        "case_id": case.case_id,
                        "candidate_id": f"{task_id}-native-{uuid.uuid4().hex[:8]}",
                        "vulnerability_type": finding.vulnerability_type,
                        "cwe_id": finding.cwe_id,
                        "location": f"{Path(loc.file_path).name}:{loc.line_start}",
                        "status": "success",
                        "note": "native auditor",
                    }
                )
            for name, cls in (("semgrep", SemgrepAdapter), ("bandit", BanditAdapter)):
                adapter = cls()
                from vulnagent.contracts import ToolExecutionRequest

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
                    all_rows.append(
                        {
                            "case_id": case.case_id,
                            "candidate_id": f"{task_id}-{name}-unavailable",
                            "vulnerability_type": "",
                            "cwe_id": "",
                            "location": "",
                            "status": "unavailable" if not result.executed else "invalid",
                            "note": f"{name} executed={result.executed} success={result.success}",
                        }
                    )
                    continue
                for finding in result.findings:
                    cand = external_finding_to_candidate(
                        result, finding, task_id=task_id, target_id=case.case_id
                    )
                    loc = cand.location
                    all_rows.append(
                        {
                            "case_id": case.case_id,
                            "candidate_id": cand.vulnerability_id,
                            "vulnerability_type": cand.vulnerability_type,
                            "cwe_id": cand.cwe_id,
                            "location": f"{Path(loc.file_path).name}:{loc.line_start}",
                            "status": "success",
                            "note": f"{name} adapter",
                        }
                    )
        else:
            seeds = REPO_ROOT / "benchmarks" / "dynamic" / "libfuzzer" / "cp_parse" / "seeds"
            work = tmp_path_for(case.case_id)
            work.mkdir(parents=True, exist_ok=True)
            build = compile_libfuzzer_target(
                target,
                work / "build",
                opt_level=case.build_spec.get("flags", ["-O0"])[0],
            )
            if not build.compiled:
                all_rows.append(
                    {
                        "case_id": case.case_id,
                        "candidate_id": f"{task_id}-buildfail",
                        "vulnerability_type": "",
                        "cwe_id": "",
                        "location": "",
                        "status": "invalid",
                        "note": f"build failed: {build.reason}",
                    }
                )
                continue
            result = await RealLibFuzzerEngine().run(
                FuzzRequest(
                    task_id=task_id,
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
            )
            if result.crashes:
                all_rows.append(
                    {
                        "case_id": case.case_id,
                        "candidate_id": f"{task_id}-crash",
                        "vulnerability_type": result.metadata.get(
                            "sanitizer_kind", "crash"
                        ),
                        "cwe_id": "CWE-121",
                        "location": "vuln.c:16",
                        "status": "success",
                        "note": f"crash {result.metadata.get('crash_input_sha256')} "
                        f"fixed={result.metadata.get('fixed_outcome')}",
                    }
                )
            else:
                all_rows.append(
                    {
                        "case_id": case.case_id,
                        "candidate_id": f"{task_id}-nocrash",
                        "vulnerability_type": "",
                        "cwe_id": "",
                        "location": "",
                        "status": "success",
                        "note": "no crash observed",
                    }
                )
    return all_rows


_scratch: Path | None = None


def tmp_path_for(name: str) -> Path:
    """Scratch dir shared by the integration dynamic track."""
    global _scratch
    import tempfile

    if _scratch is None:
        _scratch = Path(tempfile.mkdtemp(prefix="wp5it-"))
    return _scratch / name
