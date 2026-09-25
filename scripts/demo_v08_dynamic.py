"""V0.8 Dynamic Confirmation closed-loop demo.

Source candidate -> planner (dynamic validation) -> harness -> fuzz -> crash
-> associate candidate -> verification CONFIRMED, following the V0.8
acceptance chain from the master document:

    Candidate -> Planner 选择 dynamic validation -> 生成/选择 Harness
    -> libFuzzer/AFL++ (here: self-authored Python fuzz backend)
    -> ASan (here: UBSan-style semantic crash labels)
    -> Crash -> 关联 Candidate -> Verification CONFIRMED

Usage:
    python -m scripts.demo_v08_dynamic
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from vulnagent.analyzers.source.runtime import RuntimePrecheckAnalyzer
from vulnagent.contracts import (
    EvidenceV2,
    EvidenceType,
    ProjectInput,
    VerificationContext,
    VulnerabilityStatus,
)
from vulnagent.fuzz import PythonFuzzBackend
from vulnagent.fuzz.planner import DynamicValidationPlanner
from vulnagent.verification.evidence_verifier import EvidenceVerifier

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "benchmarks" / "dynamic" / "py-ubsan-001" / "app.py"
TASK_ID = "v08-dynamic"
TARGET_ID = "py-ubsan-001"
SESSION_ID = "v08-demo"


def _run_id_evidence(candidate, crash_evidence, run_id: str) -> EvidenceV2:
    """Bridge crash evidence (legacy) into an EvidenceV2 record."""
    return EvidenceV2(
        evidence_id=f"{run_id}-ev-dynamic",
        task_id=TASK_ID,
        session_id=SESSION_ID,
        evidence_type=EvidenceType.CRASH_LOG,
        producer="PythonFuzzBackend",
        analysis_run_id=run_id,
        derivation_id=f"{run_id}-dynamic-confirmation",
        independence_group="python-fuzz-crash",
        reliability=0.9,
        description="Fuzz campaign produced a reproducible runtime crash",
        data={
            "target_id": TARGET_ID,
            "crash_evidence_ids": [e.evidence_id for e in crash_evidence],
            "stage": "dynamic_confirmation",
        },
    )


async def main() -> None:
    print("=" * 72)
    print("VulnAgent V0.8 Dynamic Confirmation closed loop")
    print(f"target: {TARGET}")
    print("=" * 72)

    # 1. Static prechecks -> source candidates.
    analyzer = RuntimePrecheckAnalyzer()
    candidates = analyzer.audit(
        ProjectInput(task_id=TASK_ID, target_id=TARGET_ID, project_path=str(TARGET))
    )
    print(f"[static precheck] candidates={len(candidates)}")
    for candidate in candidates:
        print(
            f"  - {candidate.cwe_id} {candidate.title} "
            f"line={candidate.location.line_start} sink={candidate.metadata.get('sink')}"
        )

    # 2. Planner selects dynamic validation.
    planner = DynamicValidationPlanner()
    plans = [planner.plan(candidate) for candidate in candidates]
    for plan in plans:
        print(f"[planner] {plan.candidate_id} -> {plan.strategy} ({plan.rationale})")
    fuzzable = [
        (candidate, plan)
        for candidate, plan in zip(candidates, plans)
        if plan.strategy == "python-fuzz"
    ]

    if not fuzzable:
        print("[fuzz] no fuzzable candidate; nothing to confirm")
        return

    candidate, plan = fuzzable[0]
    with tempfile.TemporaryDirectory(prefix="v08_") as tmp:
        work_dir = Path(tmp)

        # 3. Fuzz campaign: harness + seeds + corpus + mutation + crash triage.
        backend = PythonFuzzBackend(seed=0)
        outcome = backend.run_campaign(
            target=TARGET,
            candidate=candidate,
            run_id="v08-run-1",
            iterations=4,
            timeout_seconds=1.0,
            session_id=SESSION_ID,
            work_dir=work_dir,
        )
        print(
            f"[fuzz] executed={outcome.executed} executions={outcome.executions} "
            f"crashes={len(outcome.crashes)} coverage={outcome.coverage}"
        )
        for crash in outcome.crashes:
            print(
                f"  - crash[{crash.crash_id}] kind={crash.kind} "
                f"exception={crash.exception_class} label={crash.sanitizer_label} "
                f"input={crash.input_bytes!r} exit={crash.exit_code}"
            )

        if not outcome.crashes:
            print("[verify] no crash; candidate stays CANDIDATE")
            return

        # 4. Associate crash evidence with the candidate.
        legacy = [e for e in outcome.evidence]
        for item in legacy:
            if item.evidence_id not in candidate.evidence_ids:
                candidate.evidence_ids.append(item.evidence_id)
        v2 = _run_id_evidence(candidate, legacy, run_id="v08-run-1")
        legacy_all = legacy + [v2.to_legacy()]

        # 5. Verification: CRASH_LOG / STACK_TRACE are probative runtime signals.
        verifier = EvidenceVerifier()
        verdict = await verifier.verify(
            candidate,
            VerificationContext(task_id=TASK_ID, evidence=legacy_all),
        )
        print(
            f"[verify] status={verdict.status.value} confidence={verdict.confidence} "
            f"stage={verdict.metadata.get('stage')}"
        )
        print(
            f"[verify] evidence={len(legacy_all)} "
            f"crash_kinds={sorted({e.evidence_type for e in legacy})}"
        )
    print("=" * 72)


if __name__ == "__main__":
    asyncio.run(main())
