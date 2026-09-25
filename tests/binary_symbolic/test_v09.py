"""V0.9 Symbolic + Autonomous Evidence Fusion tests."""

from __future__ import annotations

from pathlib import Path

from vulnagent.analyzers.binary.symbolic import (
    EvidenceFusionEvaluator,
    ReachabilityService,
    SymbolicEngine,
)
from vulnagent.contracts import VulnerabilityCandidate, VulnerabilityLocation
from vulnagent.fuzz.planner import CostAwarePlanner

STRCPY_CALLSITE = 0x140001011


def _candidate(*, callsite: str | None = "140001011", harness: bool = False, sink: str = "strcpy") -> VulnerabilityCandidate:
    metadata: dict = {"sink": sink, "source_kinds": ["stdin"]}
    if callsite:
        metadata["callsite_address"] = callsite
    if harness:
        metadata["harness_available"] = True
    return VulnerabilityCandidate(
        vulnerability_id="c1",
        task_id="t",
        title="x",
        vulnerability_type="buffer_overflow",
        cwe_id="CWE-121",
        description="x",
        target_id="x",
        location=VulnerabilityLocation(file_path="x.exe", line_start=1, line_end=1),
        source_agent="binary_analysis",
        source_type="binary",
        producer="xref",
        confidence=0.7,
        severity="HIGH",
        metadata=metadata,
    )


def test_fusion_support_independence_runtime_proof() -> None:
    fusion = EvidenceFusionEvaluator().assess(
        candidate_id="c1",
        evidence_types=["disassembly", "crash_log", "stack_trace", "fuzz_input"],
        independent_groups=["binary-xref", "python-fuzz-crash"],
        runtime_proof=True,
        reachable=True,
    )
    assert fusion.support == ["disassembly"]
    assert fusion.independence == ["binary-xref", "python-fuzz-crash"]
    assert fusion.contradiction == []
    assert fusion.runtime_proof is True


def test_fusion_contradiction_when_unreachable() -> None:
    fusion = EvidenceFusionEvaluator().assess(
        candidate_id="c1",
        evidence_types=["disassembly"],
        independent_groups=["binary-xref"],
        runtime_proof=False,
        reachable=False,
    )
    assert "symbolic_reachability_unproven" in fusion.contradiction
    assert fusion.runtime_proof is False


def test_cost_aware_planner_routes_binary_to_symbolic() -> None:
    plan = CostAwarePlanner().plan(_candidate())
    assert plan.strategy == "symbolic"
    assert plan.backend == "SymbolicEngine"
    assert plan.cost_rank == 100


def test_cost_aware_planner_prefers_cheap_fuzz() -> None:
    plan = CostAwarePlanner().plan(_candidate(harness=True, sink="div"))
    assert plan.strategy == "python-fuzz"
    assert plan.cost_rank == 10


def test_cost_aware_planner_static_fallback() -> None:
    plan = CostAwarePlanner().plan(_candidate(callsite=None, sink="deserialization"))
    assert plan.strategy == "static-only"


def test_symbolic_engine_proves_callsite_reachable(tmp_path) -> None:
    from scripts.demo_binary_v07 import make_v07_pe

    binary = tmp_path / "sample.exe"
    binary.write_bytes(make_v07_pe())
    engine = SymbolicEngine(max_steps=400, timeout_seconds=20)
    result = engine.reach(binary, STRCPY_CALLSITE)
    assert result.available is True
    assert result.reachable is True
    assert result.path_count == 1
    assert result.minimal_input is not None


def test_reachability_service_from_candidate(tmp_path) -> None:
    from scripts.demo_binary_v07 import make_v07_pe

    binary = tmp_path / "sample.exe"
    binary.write_bytes(make_v07_pe())
    candidate = _candidate()
    result = ReachabilityService(SymbolicEngine(timeout_seconds=20)).reach_candidate(binary, candidate)
    assert result.reachable is True
    assert result.target_address == STRCPY_CALLSITE
