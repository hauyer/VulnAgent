"""Evidence-gap driven planning (WP3).

The planner is the platform's own routing core: instead of a fixed call order
it inspects what evidence a candidate actually lacks (concrete location, call
path, guard/sanitizer, runtime evidence, fixed-version contrast, engine
disagreement) and picks the next bounded action.  Each action carries a budget,
permission requirement, expected evidence and a failure fallback.

Design rules (development guide section 8.2):

- ``if target not admitted: STOP(blocked)``
- ``if no concrete location: parse_or_index``
- ``if candidate has source->sink but Guard unknown: guard_recheck``
- ``if two tools disagree: independent_review``
- ``if dynamic allowed and testable local input surface: bounded_fuzz``
- ``if evidence enough for decision: verification``
- ``else: STOP(uncertain_with_missing_evidence)``

The planner is deterministic; an LLM may *suggest* actions but never bypasses
the ToolRegistry.  Supervisor keeps the final route validation and loop limits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from vulnagent.contracts import (
    AnalysisContext,
    EvidenceType,
    TargetType,
    Task,
    VulnerabilityCandidate,
)

# Candidate metadata keys the planner reads.  Native and external engines both
# write these through the audit / normalization paths (WP2).
_META_LOCATION_FILE = "location_file"
_META_LOCATION_LINE = "location_line"
_META_SINK = "sink"
_META_GUARD = "guard"
_META_TAINT_SOURCE = "source_kinds"
_META_ENTRY = "entry_point"
_META_FIXED_COMPARED = "fixed_version_compared"
_META_FUZZ_CANDIDATE = "fuzz_candidate"
_META_ENGINE = "engine"
_META_PROVIDER = "provider"


class EvidenceGapKind(str, Enum):
    """The kinds of missing evidence the planner distinguishes."""

    NO_CONCRETE_LOCATION = "no_concrete_location"
    MISSING_CALL_PATH = "missing_call_path"
    UNKNOWN_GUARD = "unknown_guard"
    MISSING_RUNTIME = "missing_runtime"
    MISSING_FIXED_CONTRAST = "missing_fixed_contrast"
    ENGINE_DISAGREEMENT = "engine_disagreement"
    EVIDENCE_SUFFICIENT = "evidence_sufficient"
    TARGET_BLOCKED = "target_blocked"


class PlannedAction(str, Enum):
    """Bounded next actions the planner may request."""

    PARSE_OR_INDEX = "parse_or_index"
    GUARD_RECHECK = "guard_recheck"
    INDEPENDENT_REVIEW = "independent_review"
    BOUNDED_FUZZ = "bounded_fuzz"
    VERIFICATION = "verification"
    STOP_BLOCKED = "stop_blocked"
    STOP_UNCERTAIN = "stop_uncertain_missing_evidence"


@dataclass(frozen=True, slots=True)
class ActionBinding:
    """Budget, permission, expected evidence and fallback for one action."""

    action: PlannedAction
    budget_seconds: int
    permission_required: str
    expected_evidence: str
    failure_fallback: PlannedAction


@dataclass(slots=True)
class CandidateGap:
    """The evidence-gap summary for a single candidate."""

    candidate: VulnerabilityCandidate
    gap_kind: EvidenceGapKind
    reason: str
    components: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PlanDecision:
    """The planner's deterministic decision for the current context."""

    action: PlannedAction
    gap_kind: EvidenceGapKind
    rationale: str
    candidate_id: str | None = None
    binding: ActionBinding | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


_ACTION_BINDINGS: dict[PlannedAction, ActionBinding] = {
    PlannedAction.PARSE_OR_INDEX: ActionBinding(
        action=PlannedAction.PARSE_OR_INDEX,
        budget_seconds=120,
        permission_required="static_read",
        expected_evidence="concrete file/function/line location",
        failure_fallback=PlannedAction.STOP_UNCERTAIN,
    ),
    PlannedAction.GUARD_RECHECK: ActionBinding(
        action=PlannedAction.GUARD_RECHECK,
        budget_seconds=120,
        permission_required="static_read",
        expected_evidence="guard/sanitizer presence and reachability",
        failure_fallback=PlannedAction.STOP_UNCERTAIN,
    ),
    PlannedAction.INDEPENDENT_REVIEW: ActionBinding(
        action=PlannedAction.INDEPENDENT_REVIEW,
        budget_seconds=120,
        permission_required="static_read",
        expected_evidence="independent engine or reviewer verdict",
        failure_fallback=PlannedAction.VERIFICATION,
    ),
    PlannedAction.BOUNDED_FUZZ: ActionBinding(
        action=PlannedAction.BOUNDED_FUZZ,
        budget_seconds=300,
        permission_required="dynamic_run",
        expected_evidence="runtime trace / crash / sanitizer output",
        failure_fallback=PlannedAction.GUARD_RECHECK,
    ),
    PlannedAction.VERIFICATION: ActionBinding(
        action=PlannedAction.VERIFICATION,
        budget_seconds=120,
        permission_required="static_read",
        expected_evidence="verification verdict with missing-evidence list",
        failure_fallback=PlannedAction.STOP_UNCERTAIN,
    ),
}


class EvidenceGapPlanner:
    """Deterministic evidence-gap planner.

    Pure and side-effect free: it reads ``AnalysisContext`` and returns a
    ``PlanDecision``.  It never executes tools and never mutates state.
    """

    def __init__(
        self,
        *,
        fuzz_budget_seconds: int = 300,
        guard_recheck_budget_seconds: int = 120,
    ) -> None:
        self.fuzz_budget_seconds = fuzz_budget_seconds
        self.guard_recheck_budget_seconds = guard_recheck_budget_seconds

    def plan(
        self,
        task: Task,
        context: AnalysisContext,
    ) -> PlanDecision:
        """Decide the next bounded action from accumulated evidence gaps."""

        if not self._admitted(task):
            return PlanDecision(
                action=PlannedAction.STOP_BLOCKED,
                gap_kind=EvidenceGapKind.TARGET_BLOCKED,
                rationale="target is not admitted; analysis is blocked",
                metadata={"admitted": False},
            )

        if not context.findings:
            return PlanDecision(
                action=PlannedAction.PARSE_OR_INDEX,
                gap_kind=EvidenceGapKind.NO_CONCRETE_LOCATION,
                rationale="no candidate yet; need parse/index to find concrete locations",
                binding=_ACTION_BINDINGS[PlannedAction.PARSE_OR_INDEX],
            )

        # Prefer the highest-priority candidate for gap analysis.
        ranked = sorted(
            context.findings,
            key=lambda item: item.confidence,
            reverse=True,
        )
        target_candidate = ranked[0]

        if not self._has_location(target_candidate):
            return PlanDecision(
                action=PlannedAction.PARSE_OR_INDEX,
                gap_kind=EvidenceGapKind.NO_CONCRETE_LOCATION,
                rationale=(
                    f"candidate {target_candidate.vulnerability_id} lacks a "
                    "concrete location"
                ),
                candidate_id=target_candidate.vulnerability_id,
                binding=_ACTION_BINDINGS[PlannedAction.PARSE_OR_INDEX],
            )

        if self._missing_call_path(target_candidate, context):
            return PlanDecision(
                action=PlannedAction.GUARD_RECHECK,
                gap_kind=EvidenceGapKind.MISSING_CALL_PATH,
                rationale=(
                    f"candidate {target_candidate.vulnerability_id} has a sink "
                    "but no call path evidence"
                ),
                candidate_id=target_candidate.vulnerability_id,
                binding=_ACTION_BINDINGS[PlannedAction.GUARD_RECHECK],
            )

        if self._guard_unknown(target_candidate, context):
            return PlanDecision(
                action=PlannedAction.GUARD_RECHECK,
                gap_kind=EvidenceGapKind.UNKNOWN_GUARD,
                rationale=(
                    f"candidate {target_candidate.vulnerability_id} has "
                    "source->sink but the guard/sanitizer is unknown"
                ),
                candidate_id=target_candidate.vulnerability_id,
                binding=_ACTION_BINDINGS[PlannedAction.GUARD_RECHECK],
            )

        if self._engines_disagree(context):
            return PlanDecision(
                action=PlannedAction.INDEPENDENT_REVIEW,
                gap_kind=EvidenceGapKind.ENGINE_DISAGREEMENT,
                rationale="independent engines disagree on a candidate",
                candidate_id=target_candidate.vulnerability_id,
                binding=_ACTION_BINDINGS[PlannedAction.INDEPENDENT_REVIEW],
            )

        if self._fuzz_wanted(task, target_candidate, context):
            return PlanDecision(
                action=PlannedAction.BOUNDED_FUZZ,
                gap_kind=EvidenceGapKind.MISSING_RUNTIME,
                rationale=(
                    f"candidate {target_candidate.vulnerability_id} has a "
                    "testable local input surface and dynamic execution is "
                    "authorized"
                ),
                candidate_id=target_candidate.vulnerability_id,
                binding=_ACTION_BINDINGS[PlannedAction.BOUNDED_FUZZ],
            )

        if not self._fixed_contrast_present(target_candidate):
            return PlanDecision(
                action=PlannedAction.GUARD_RECHECK,
                gap_kind=EvidenceGapKind.MISSING_FIXED_CONTRAST,
                rationale=(
                    f"candidate {target_candidate.vulnerability_id} lacks "
                    "fixed-version contrast evidence"
                ),
                candidate_id=target_candidate.vulnerability_id,
                binding=_ACTION_BINDINGS[PlannedAction.GUARD_RECHECK],
            )

        if self._evidence_sufficient(target_candidate, context):
            return PlanDecision(
                action=PlannedAction.VERIFICATION,
                gap_kind=EvidenceGapKind.EVIDENCE_SUFFICIENT,
                rationale=(
                    f"candidate {target_candidate.vulnerability_id} has enough "
                    "evidence for an independent verdict"
                ),
                candidate_id=target_candidate.vulnerability_id,
                binding=_ACTION_BINDINGS[PlannedAction.VERIFICATION],
            )

        return PlanDecision(
            action=PlannedAction.STOP_UNCERTAIN,
            gap_kind=EvidenceGapKind.MISSING_RUNTIME,
            rationale=(
                f"candidate {target_candidate.vulnerability_id} remains "
                "uncertain with missing evidence"
            ),
            candidate_id=target_candidate.vulnerability_id,
        )

    # -- deterministic predicates ------------------------------------------

    @staticmethod
    def _admitted(task: Task) -> bool:
        return bool(task.target.metadata.get("admitted", True))

    @staticmethod
    def _has_location(candidate: VulnerabilityCandidate) -> bool:
        location = candidate.location
        if location is None:
            return False
        return bool(location.file_path or location.binary_address or location.module_name)

    @staticmethod
    def _missing_call_path(
        candidate: VulnerabilityCandidate,
        context: AnalysisContext,
    ) -> bool:
        has_path = any(
            item.evidence_type in {EvidenceType.CALL_PATH, EvidenceType.DATA_FLOW}
            for item in context.evidence
            if item.evidence_id in (candidate.evidence_ids or [])
        )
        sink = (candidate.metadata or {}).get(_META_SINK)
        return bool(sink) and not has_path

    @staticmethod
    def _guard_unknown(
        candidate: VulnerabilityCandidate,
        context: AnalysisContext,
    ) -> bool:
        guard = (candidate.metadata or {}).get(_META_GUARD)
        if guard:
            return False
        guard_evidence = any(
            item.evidence_type in {EvidenceType.TAINT_PATH, EvidenceType.DATA_FLOW}
            and bool((item.data or {}).get("guard"))
            for item in context.evidence
            if item.evidence_id in (candidate.evidence_ids or [])
        )
        return not guard_evidence

    @staticmethod
    def _engines_disagree(context: AnalysisContext) -> bool:
        providers = {
            str(item.metadata.get(_META_PROVIDER) or item.metadata.get(_META_ENGINE) or "")
            for item in context.findings
        }
        providers.discard("")
        return len(providers) >= 2

    def _fuzz_wanted(
        self,
        task: Task,
        candidate: VulnerabilityCandidate,
        context: AnalysisContext,
    ) -> bool:
        metadata = task.target.metadata
        dynamic_allowed = bool(
            metadata.get("dynamic_allowed") or metadata.get("fuzz_authorized")
        )
        if not dynamic_allowed:
            return False
        if candidate.metadata.get(_META_FUZZ_CANDIDATE) is False:
            return False
        entry = candidate.metadata.get(_META_ENTRY) or metadata.get("input_surface")
        return bool(entry)

    @staticmethod
    def _fixed_contrast_present(candidate: VulnerabilityCandidate) -> bool:
        return bool(candidate.metadata.get(_META_FIXED_COMPARED))

    @staticmethod
    def _evidence_sufficient(
        candidate: VulnerabilityCandidate,
        context: AnalysisContext,
    ) -> bool:
        owned = {
            item.evidence_id
            for item in context.evidence
            if item.evidence_id in (candidate.evidence_ids or [])
        }
        return len(owned) >= 1


__all__ = [
    "ActionBinding",
    "CandidateGap",
    "EvidenceGapKind",
    "EvidenceGapPlanner",
    "PlanDecision",
    "PlannedAction",
]
