"""V0.9 Symbolic + Autonomous Evidence Fusion closed-loop demo.

When fuzzing cannot enter a candidate path (binary target with no native
harness), the V0.9 acceptance chain applies:

    Static Candidate -> angr Reachability -> Constraint
    -> Controlled Input -> Dynamic Validation

Pipeline: V0.7 IAT xref finds the dangerous callsite -> CostAwarePlanner
routes to angr (fuzz has no harness) -> SymbolicEngine proves reachability
and solves a minimal input -> the input seeds the equivalent dynamic target
-> a real crash provides runtime proof -> Evidence Fusion reports support /
independence / runtime proof.

Usage:
    python -m scripts.demo_v09_symbolic
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from vulnagent.analyzers.binary.intel import BinaryXrefAnalyzer
from vulnagent.analyzers.binary.reverse import StaticBinaryReverseAnalyzer
from vulnagent.analyzers.binary.symbolic import EvidenceFusionEvaluator, ReachabilityService
from vulnagent.contracts import (
    BinaryAnalysisRequest,
    EvidenceV2,
    EvidenceType,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)
from vulnagent.fuzz import PythonFuzzBackend
from vulnagent.fuzz.planner import CostAwarePlanner

from scripts.demo_binary_v07 import IMAGE_BASE, make_v07_pe  # type: ignore[import-not-found]

ROOT = Path(__file__).resolve().parents[1]
TASK_ID = "v09-symbolic"
TARGET_ID = "synthetic-pe64-gets-strcpy"
SESSION_ID = "v09-demo"
STRCPY_CALLSITE = 0x140001011


def _candidate_from_xref(xref_result: dict, *, task_id: str, target_id: str) -> VulnerabilityCandidate:
    chain = xref_result["chains"][0]
    return VulnerabilityCandidate(
        vulnerability_id="v09-binary-candidate",
        task_id=task_id,
        title="Unbounded copy via strcpy from gets input",
        vulnerability_type="buffer_overflow",
        cwe_id="CWE-121",
        description=(
            f"{chain['input_api']} reaches dangerous {chain['dangerous_api']} "
            f"in stripped function {chain['function_id']}"
        ),
        target_id=target_id,
        location=VulnerabilityLocation(
            file_path="sample.exe", line_start=STRCPY_CALLSITE, line_end=STRCPY_CALLSITE
        ),
        source_agent="binary_analysis",
        source_type="binary",
        producer="pe-x64-iat-xref",
        confidence=0.7,
        severity="HIGH",
        metadata={
            "sink": "strcpy",
            "source_kinds": ["stdin"],
            "callsite_address": f"{STRCPY_CALLSITE:x}",
        },
    )


async def main() -> None:
    print("=" * 72)
    print("VulnAgent V0.9 Symbolic + Autonomous Evidence Fusion closed loop")
    print("=" * 72)

    fixture = make_v07_pe()
    work_root = ROOT / ".pytest-tmp" / "v09_demo_out"
    work_root.mkdir(parents=True, exist_ok=True)
    binary = work_root / "sample.exe"
    binary.write_bytes(fixture)

    # 1. Static candidate: V0.7 IAT xref -> dangerous callsite.
    parser = StaticBinaryReverseAnalyzer()
    parsed = await parser.analyze(
        BinaryAnalysisRequest(task_id=TASK_ID, target_id=TARGET_ID, path=str(binary))
    )
    xref = BinaryXrefAnalyzer(
        data=fixture,
        sections=parsed.metadata.get("sections", []),
        import_entries=parsed.metadata.get("format_details", {}).get("import_entries", []),
        image_base=IMAGE_BASE,
    ).analyze()
    candidate = _candidate_from_xref(xref, task_id=TASK_ID, target_id=TARGET_ID)
    print(f"[static] candidate {candidate.cwe_id} callsite={STRCPY_CALLSITE:x} "
          f"(no native harness -> fuzz cannot enter this path)")

    # 2. Cost-aware planner.
    plan = CostAwarePlanner().plan(candidate)
    print(f"[planner] {plan.strategy} cost_rank={plan.cost_rank} ({plan.rationale})")

    # 3. angr reachability + constraint summary + minimal input.
    service = ReachabilityService()
    result = service.reach_candidate(binary, candidate)
    print(f"[angr] available={result.available} reachable={result.reachable} "
          f"paths={result.path_count}")
    print(f"[angr] constraint_summary={result.constraint_summary[:3]}")
    print(f"[angr] minimal_input={result.minimal_input!r}")
    if not result.reachable:
        print(f"[angr] FAILED reason={result.reason}")
        return

    # 4. Controlled input -> dynamic validation on the equivalent target.
    # The unbounded-copy semantics need an input longer than the 16-byte fixed
    # buffer; the angr-solved input is used as the seed and derived controlled
    # inputs exercise the CWE-121 trigger condition deterministically.
    equivalent = ROOT / "benchmarks" / "dynamic" / "py-symbolic-001" / "app.py"
    from vulnagent.fuzz.executor import ControlledExecutor
    from vulnagent.fuzz.triage import CrashTriage

    executor = ControlledExecutor(timeout_seconds=1.0)
    triage = CrashTriage()
    controlled_inputs = [
        result.minimal_input or b"",
        (result.minimal_input or b"") + b"A" * 32,
        b"A" * 40,
    ]
    crashes: list = []
    ctrl_dir = work_root / "ctrl"
    ctrl_dir.mkdir(parents=True, exist_ok=True)
    for index, payload in enumerate(controlled_inputs):
        run = executor.execute(equivalent, payload, ctrl_dir)
        record = triage.classify(
            execution=run,
            input_bytes=payload,
            task_id=TASK_ID,
            target_id="py-symbolic-001",
            run_id="v09-run-1",
            index=index,
        )
        if record is not None:
            crashes.append(record)
    print(f"[dynamic] controlled_inputs={len(controlled_inputs)} crashes={len(crashes)}")
    for crash in crashes:
        print(f"  - {crash.exception_class} label={crash.sanitizer_label} "
              f"input={crash.input_bytes!r}")

    # 5. Evidence fusion: support / independence / runtime proof.
    evidence_types = ["disassembly", "crash_log", "stack_trace", "fuzz_input"]
    fusion = EvidenceFusionEvaluator().assess(
        candidate_id=candidate.vulnerability_id,
        evidence_types=evidence_types,
        independent_groups=["binary-xref", "python-fuzz-crash"],
        runtime_proof=bool(crashes),
        reachable=result.reachable,
    )
    print(f"[fusion] {fusion.summary}")
    print(f"[fusion] support={fusion.support} independence={fusion.independence} "
          f"contradiction={fusion.contradiction} runtime_proof={fusion.runtime_proof}")
    print(
        f"[verdict] reachability=symbolic_proven runtime_proof={fusion.runtime_proof} "
        f"evidence_count={2 + 3 * len(crashes)}"
    )
    print("=" * 72)


def _equivalent_candidate(original: VulnerabilityCandidate, path: Path) -> VulnerabilityCandidate:
    """Source counterpart of the binary candidate for the fuzz leg."""
    return VulnerabilityCandidate(
        vulnerability_id="v09-symbolic-equiv",
        task_id=original.task_id,
        title=original.title,
        vulnerability_type=original.vulnerability_type,
        cwe_id=original.cwe_id,
        description=original.description,
        target_id="py-symbolic-001",
        location=VulnerabilityLocation(
            file_path=str(path), line_start=1, line_end=20
        ),
        source_agent="source_audit",
        source_type="source",
        producer="runtime-precheck",
        confidence=0.6,
        severity="WARNING",
        metadata={"sink": "subscript", "source_kinds": ["file_input"]},
    )


if __name__ == "__main__":
    asyncio.run(main())
