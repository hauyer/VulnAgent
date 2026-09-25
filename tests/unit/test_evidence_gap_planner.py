"""WP3 tests: evidence-gap driven planning and supervisor routing.

Covers the deterministic rule chain (development guide 8.2), action bindings
with budget/permission/expected-evidence/fallback, and the Supervisor
translation of plans into validated routes (including budget-exhaustion
fallbacks and loop protection).
"""

from __future__ import annotations

import pytest

from vulnagent.agent_runtime import (
    AgentRoute,
    EvidenceGapKind,
    EvidenceGapPlanner,
    PlannedAction,
    Supervisor,
)
from vulnagent.agent_runtime.state import initial_runtime_state
from vulnagent.contracts import (
    AgentMessage,
    AnalysisContext,
    Evidence,
    EvidenceType,
    Target,
    TargetType,
    Task,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)


def _target(*, admitted: bool = True, fuzz_authorized: bool = False, **metadata) -> Target:
    values = {"admitted": admitted, "fuzz_authorized": fuzz_authorized}
    values.update(metadata)
    return Target(
        target_id="t1",
        path="app.py",
        target_type=TargetType.SOURCE,
        metadata=values,
    )


def _candidate(
    *,
    candidate_id: str = "c1",
    confidence: float = 0.8,
    location: VulnerabilityLocation | None = None,
    sink: str | None = "subprocess.run",
    guard: str | None = None,
    entry_point: str | None = None,
    fixed_compared: bool = False,
    provider: str | None = None,
    evidence_ids: list[str] | None = None,
) -> VulnerabilityCandidate:
    metadata: dict = {}
    if sink is not None:
        metadata["sink"] = sink
    if guard is not None:
        metadata["guard"] = guard
    if entry_point is not None:
        metadata["entry_point"] = entry_point
    if fixed_compared:
        metadata["fixed_version_compared"] = True
    if provider is not None:
        metadata["provider"] = provider
    return VulnerabilityCandidate(
        vulnerability_id=candidate_id,
        task_id="task-1",
        title="candidate",
        vulnerability_type="command_injection",
        cwe_id="CWE-78",
        description="test",
        target_id="t1",
        location=location,
        source_agent="source_audit",
        confidence=confidence,
        evidence_ids=evidence_ids or [],
        metadata=metadata,
    )


def _evidence(evidence_id: str, evidence_type: EvidenceType = EvidenceType.CALL_PATH) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        task_id="task-1",
        evidence_type=evidence_type,
        source="parser",
        description="evidence",
        reliability=0.8,
        created_by="test",
    )


def _context(*, candidates: list[VulnerabilityCandidate], evidence: list[Evidence] | None = None) -> AnalysisContext:
    task = Task(task_id="task-1", target=_target())
    return AnalysisContext(
        task=task,
        findings=candidates,
        evidence=evidence or [],
    )


LOC = VulnerabilityLocation(file_path="app.py", line_start=8)


def test_blocked_target_stops() -> None:
    task = Task(task_id="t", target=_target(admitted=False))
    context = AnalysisContext(task=task)
    decision = EvidenceGapPlanner().plan(task, context)
    assert decision.action is PlannedAction.STOP_BLOCKED
    assert decision.gap_kind is EvidenceGapKind.TARGET_BLOCKED


def test_no_candidate_requests_parse_or_index() -> None:
    task = Task(task_id="t", target=_target())
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[]))
    assert decision.action is PlannedAction.PARSE_OR_INDEX
    assert decision.binding is not None
    assert decision.binding.permission_required == "static_read"
    assert decision.binding.failure_fallback is PlannedAction.STOP_UNCERTAIN


def test_candidate_without_location_requests_parse() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(location=None, sink=None)
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[candidate]))
    assert decision.action is PlannedAction.PARSE_OR_INDEX
    assert decision.candidate_id == "c1"


def test_candidate_with_sink_but_no_call_path_requests_guard_recheck() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(location=LOC, sink="subprocess.run")
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[candidate]))
    assert decision.action is PlannedAction.GUARD_RECHECK
    assert decision.gap_kind is EvidenceGapKind.MISSING_CALL_PATH


def test_call_path_evidence_satisfies_path_gap() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(location=LOC, evidence_ids=["ev-call"])
    evidence = [
        _evidence("ev-call")
    ]
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[candidate], evidence=evidence))
    # guard unknown now becomes the deciding gap
    assert decision.action is PlannedAction.GUARD_RECHECK
    assert decision.gap_kind is EvidenceGapKind.UNKNOWN_GUARD


def test_known_guard_skips_guard_recheck() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(
        location=LOC,
        guard="shlex.quote",
        fixed_compared=True,
        evidence_ids=["ev-call"],
    )
    evidence = [
        _evidence("ev-call")
    ]
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[candidate], evidence=evidence))
    assert decision.action is not PlannedAction.GUARD_RECHECK


def test_engine_disagreement_requests_independent_review() -> None:
    task = Task(task_id="t", target=_target())
    native = _candidate(candidate_id="c1", location=LOC, guard="g", provider="native", evidence_ids=["ev-call"])
    external = _candidate(candidate_id="c2", location=LOC, guard="g", provider="semgrep", evidence_ids=["ev-call"])
    evidence = [
        _evidence("ev-call")
    ]
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[native, external], evidence=evidence))
    assert decision.action is PlannedAction.INDEPENDENT_REVIEW
    assert decision.gap_kind is EvidenceGapKind.ENGINE_DISAGREEMENT


def test_authorized_fuzz_with_entry_requests_bounded_fuzz() -> None:
    task = Task(task_id="t", target=_target(fuzz_authorized=True, dynamic_allowed=True))
    candidate = _candidate(location=LOC, guard="g", entry_point="parse", evidence_ids=["ev-call"])
    evidence = [
        _evidence("ev-call")
    ]
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[candidate], evidence=evidence))
    assert decision.action is PlannedAction.BOUNDED_FUZZ
    assert decision.binding.permission_required == "dynamic_run"
    assert decision.binding.failure_fallback is PlannedAction.GUARD_RECHECK


def test_fuzz_not_authorized_skips_bounded_fuzz() -> None:
    task = Task(task_id="t", target=_target(fuzz_authorized=False))
    candidate = _candidate(location=LOC, guard="g", entry_point="parse", evidence_ids=["ev-call"])
    evidence = [
        _evidence("ev-call")
    ]
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[candidate], evidence=evidence))
    assert decision.action is not PlannedAction.BOUNDED_FUZZ


def test_missing_fixed_contrast_requests_guard_recheck() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(location=LOC, guard="g", evidence_ids=["ev-call"], fixed_compared=False)
    evidence = [
        _evidence("ev-call")
    ]
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[candidate], evidence=evidence))
    assert decision.action is PlannedAction.GUARD_RECHECK
    assert decision.gap_kind is EvidenceGapKind.MISSING_FIXED_CONTRAST


def test_sufficient_evidence_requests_verification() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(
        location=LOC,
        guard="g",
        fixed_compared=True,
        evidence_ids=["ev-call"],
    )
    evidence = [
        _evidence("ev-call")
    ]
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[candidate], evidence=evidence))
    assert decision.action is PlannedAction.VERIFICATION
    assert decision.gap_kind is EvidenceGapKind.EVIDENCE_SUFFICIENT


def test_uncertain_stop_when_evidence_still_missing() -> None:
    task = Task(task_id="t", target=_target())
    # no sink and no owned evidence: path/guard/fixed-contrast checks pass,
    # but the remaining evidence gap (nothing to present to verification)
    # stops as uncertain
    candidate = _candidate(
        location=LOC, sink=None, guard="g", fixed_compared=True, evidence_ids=[]
    )
    decision = EvidenceGapPlanner().plan(task, _context(candidates=[candidate]))
    assert decision.action is PlannedAction.STOP_UNCERTAIN


def test_planner_is_deterministic() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(location=LOC, guard="g", fixed_compared=True, evidence_ids=["ev-call"])
    context = _context(
        candidates=[candidate],
        evidence=[_evidence("ev-call")],
    )
    first = EvidenceGapPlanner().plan(task, context)
    second = EvidenceGapPlanner().plan(task, context)
    assert first.action is second.action
    assert first.rationale == second.rationale


# -- Supervisor routing ----------------------------------------------------


def _supervisor_state(current: str, history: list[str] | None = None) -> dict:
    state = initial_runtime_state("task-1")
    state["current_agent"] = current
    state["route_history"] = history or [current]
    return state


def test_supervisor_routes_blocked_to_finish() -> None:
    task = Task(task_id="t", target=_target(admitted=False))
    context = AnalysisContext(task=task)
    decision = Supervisor(gap_planner=EvidenceGapPlanner()).decide(
        task, context, _supervisor_state(AgentRoute.SOURCE_ANALYSIS.value)
    )
    assert decision.route is AgentRoute.FINISH


def test_supervisor_routes_guard_recheck_gap_to_verification() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(location=LOC, sink="subprocess.run")
    context = _context(candidates=[candidate])
    decision = Supervisor(gap_planner=EvidenceGapPlanner()).decide(
        task, context, _supervisor_state(AgentRoute.SOURCE_ANALYSIS.value)
    )
    # source analysis already ran; the missing call-path fact cannot be
    # manufactured by re-running the same engine, so the gap is handed to
    # independent verification with the gap recorded in metadata.
    assert decision.route is AgentRoute.VERIFICATION
    assert decision.metadata.get("gap_kind") == "missing_call_path"


def test_supervisor_guard_recheck_gap_falls_back_with_metadata() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(location=LOC, sink="subprocess.run")
    context = _context(candidates=[candidate])
    decision = Supervisor(gap_planner=EvidenceGapPlanner()).decide(
        task,
        context,
        _supervisor_state(
            AgentRoute.SOURCE_ANALYSIS.value,
            history=[AgentRoute.SOURCE_ANALYSIS.value, AgentRoute.SOURCE_ANALYSIS.value],
        ),
    )
    assert decision.route is AgentRoute.VERIFICATION
    assert decision.metadata.get("gap_kind") == "missing_call_path"


def test_supervisor_guard_recheck_gap_honors_requested_fuzz_first() -> None:
    task = Task(task_id="t", target=_target(fuzz_authorized=True, dynamic_allowed=True))
    candidate = _candidate(location=LOC, sink="subprocess.run")
    message = AgentMessage(
        message_id="m1",
        task_id="task-1",
        sender="planner",
        receiver="runtime",
        message_type="plan",
        payload={"requested_capabilities": ["fuzz.execute"]},
    )
    context = _context(candidates=[candidate])
    context.messages.append(message)
    decision = Supervisor(gap_planner=EvidenceGapPlanner()).decide(
        task, context, _supervisor_state(AgentRoute.SOURCE_ANALYSIS.value)
    )
    assert decision.route is AgentRoute.FUZZ


def test_supervisor_routes_fuzz_with_budget_metadata() -> None:
    task = Task(task_id="t", target=_target(fuzz_authorized=True, dynamic_allowed=True))
    candidate = _candidate(location=LOC, guard="g", entry_point="parse", evidence_ids=["ev-call"])
    evidence = [
        _evidence("ev-call")
    ]
    context = _context(candidates=[candidate], evidence=evidence)
    decision = Supervisor(gap_planner=EvidenceGapPlanner()).decide(
        task, context, _supervisor_state(AgentRoute.SOURCE_ANALYSIS.value)
    )
    assert decision.route is AgentRoute.FUZZ
    assert decision.metadata.get("budget_seconds") == 300
    assert decision.metadata.get("permission_required") == "dynamic_run"


def test_supervisor_fuzz_already_ran_forwards_to_verification() -> None:
    task = Task(task_id="t", target=_target(fuzz_authorized=True, dynamic_allowed=True))
    candidate = _candidate(location=LOC, guard="g", entry_point="parse", evidence_ids=["ev-call"])
    evidence = [
        _evidence("ev-call")
    ]
    context = _context(candidates=[candidate], evidence=evidence)
    decision = Supervisor(gap_planner=EvidenceGapPlanner()).decide(
        task,
        context,
        _supervisor_state(
            AgentRoute.SOURCE_ANALYSIS.value,
            history=[AgentRoute.SOURCE_ANALYSIS.value, AgentRoute.FUZZ.value],
        ),
    )
    assert decision.route is AgentRoute.VERIFICATION


def test_supervisor_routes_verification_when_evidence_sufficient() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(
        location=LOC,
        guard="g",
        fixed_compared=True,
        evidence_ids=["ev-call"],
    )
    evidence = [
        _evidence("ev-call")
    ]
    context = _context(candidates=[candidate], evidence=evidence)
    decision = Supervisor(gap_planner=EvidenceGapPlanner()).decide(
        task, context, _supervisor_state(AgentRoute.SOURCE_ANALYSIS.value)
    )
    assert decision.route is AgentRoute.VERIFICATION


def test_supervisor_without_gap_planner_keeps_legacy_order() -> None:
    task = Task(task_id="t", target=_target())
    candidate = _candidate(location=LOC)
    context = _context(candidates=[candidate])
    decision = Supervisor().decide(
        task, context, _supervisor_state(AgentRoute.SOURCE_ANALYSIS.value)
    )
    # legacy behavior: candidates go straight to verification
    assert decision.route is AgentRoute.VERIFICATION
