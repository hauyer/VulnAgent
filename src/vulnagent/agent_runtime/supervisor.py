"""Deterministic V0.2 supervisor for context-aware agent selection."""

from collections.abc import Callable
from typing import Any

from vulnagent.contracts import AnalysisContext, TargetType, Task

from .evidence_gap import EvidenceGapPlanner, PlanDecision, PlannedAction
from .router import AgentRoute, RouteDecision
from .state import RuntimeState


class Supervisor:
    """Choose the next specialized agent without executing capabilities.

    When an ``EvidenceGapPlanner`` is injected, source-analysis follow-up is
    driven by evidence gaps (WP3); otherwise the fixed V0.2 order applies.
    The planner may request a bounded action; this supervisor still validates
    it against routes, budgets and loop limits before dispatch.
    """

    def __init__(
        self,
        max_analysis_retries: int = 1,
        available_routes: set[str] | None = None,
        gap_planner: EvidenceGapPlanner | None = None,
        profile_hint_reader: Callable[[Task], set[str] | None] | None = None,
    ) -> None:
        if max_analysis_retries < 0:
            raise ValueError(
                "max_analysis_retries cannot be negative"
            )

        self.max_analysis_retries = max_analysis_retries
        self.available_routes = available_routes
        self.gap_planner = gap_planner
        self.profile_hint_reader = profile_hint_reader
        self._gap_plan: PlanDecision | None = None

    def decide(self, task: Task, context: AnalysisContext, state: RuntimeState) -> RouteDecision:
        """Select a structured route from task type and accumulated results."""
        current = state["current_agent"]
        history = state["route_history"]
        if current is None:
            return RouteDecision(AgentRoute.PLANNER, "initialize a structured plan")
        if current == AgentRoute.PLANNER.value:
            route = (
                AgentRoute.PROGRAM_RESTORATION
                if self._protected_binary(task) and self._available(AgentRoute.PROGRAM_RESTORATION, task)
                else AgentRoute.BINARY_ANALYSIS
                if task.target.target_type is TargetType.BINARY
                else AgentRoute.SOURCE_ANALYSIS
            )
            return RouteDecision(route, "route by target type")
        if current == AgentRoute.PROGRAM_RESTORATION.value:
            return RouteDecision(AgentRoute.BINARY_ANALYSIS, "restoration evidence is ready for binary analysis")
        if (
            current == AgentRoute.BINARY_ANALYSIS.value
            and self._protected_binary(task)
            and self._available(AgentRoute.CODE_DEOBFUSCATION, task)
        ):
            if history.count(AgentRoute.CODE_DEOBFUSCATION.value) < history.count(AgentRoute.BINARY_ANALYSIS.value):
                return RouteDecision(AgentRoute.CODE_DEOBFUSCATION, "recover protected code semantics before vulnerability verification")
        if (
            current == AgentRoute.SOURCE_ANALYSIS.value
            and self._available(AgentRoute.CODE_AUDIT, task)
            and history.count(AgentRoute.CODE_AUDIT.value)
            < history.count(AgentRoute.SOURCE_ANALYSIS.value)
            and any(
                item.metadata.get("audit_domain") == "software_code"
                for item in context.findings
            )
        ):
            return RouteDecision(
                AgentRoute.CODE_AUDIT,
                "software-code candidates require bounded semantic review",
            )
        if current in {
            AgentRoute.SOURCE_ANALYSIS.value,
            AgentRoute.BINARY_ANALYSIS.value,
            AgentRoute.CODE_DEOBFUSCATION.value,
            AgentRoute.CODE_AUDIT.value,
        }:
            if self.gap_planner is not None and current == AgentRoute.SOURCE_ANALYSIS.value:
                return self._route_by_evidence_gap(task, context, history)
            if not context.findings:
                # Authorized dynamic discovery must not be blocked by the
                # absence of static findings (blind discovery runs produce
                # candidates from execution, not from static review).
                if self._fuzz_requested(task, context) and AgentRoute.FUZZ.value not in history:
                    return RouteDecision(
                        AgentRoute.FUZZ,
                        "authorized dynamic discovery requested despite no static findings",
                    )
                return RouteDecision(AgentRoute.REPORT, "analysis completed without findings")
            if self._fuzz_requested(task, context) and AgentRoute.FUZZ.value not in history:
                return RouteDecision(AgentRoute.FUZZ, "authorized dynamic evidence was requested")
            return RouteDecision(AgentRoute.VERIFICATION, "candidate requires independent verification")
        if current == AgentRoute.FUZZ.value:
            return RouteDecision(AgentRoute.VERIFICATION, "dynamic evidence is ready for verification")
        if current == AgentRoute.VERIFICATION.value:
            verification_messages = [
                message
                for message in context.messages
                if message.message_type.value == "verification_result"
            ]

            retry_requested = bool(
                verification_messages
                and verification_messages[-1].payload.get(
                    "request_additional_analysis",
                    False,
                )
            )

            attempts = int(
                state["runtime_metadata"].get(
                    "analysis_retries",
                    0,
                )
            )

            if retry_requested:
                if attempts < self.max_analysis_retries:
                    route = (
                        AgentRoute.BINARY_ANALYSIS
                        if task.target.target_type is TargetType.BINARY
                        else AgentRoute.SOURCE_ANALYSIS
                    )

                    return RouteDecision(
                        route,
                        "verification requested bounded additional analysis",
                        metadata={
                            "retry": True,
                            "analysis_retry_attempt": attempts + 1,
                        },
                    )

                return RouteDecision(
                    AgentRoute.REVIEWER,
                    "analysis retry limit reached; continue to review",
                    metadata={
                        "retry_exhausted": True,
                    },
                )

            return RouteDecision(
                AgentRoute.REVIEWER,
                "verification results require independent review",
            )
        if current == AgentRoute.REVIEWER.value:
            return RouteDecision(AgentRoute.REPORT, "review complete")
        if current == AgentRoute.REPORT.value:
            return RouteDecision(AgentRoute.FINISH, "report generated")
        return RouteDecision(AgentRoute.REPORT, "unknown runtime state", fallback_used=True)

    def _route_by_evidence_gap(
        self,
        task: Task,
        context: AnalysisContext,
        history: list[str],
    ) -> RouteDecision:
        """Translate the evidence-gap plan into a validated supervisor route."""

        assert self.gap_planner is not None
        plan = self.gap_planner.plan(task, context)
        self._gap_plan = plan
        action = plan.action

        # stop actions terminate safely; block means the target never ran.
        if action is PlannedAction.STOP_BLOCKED:
            return RouteDecision(
                AgentRoute.FINISH,
                "target blocked; no analysis is permitted",
                metadata={"gap_kind": plan.gap_kind.value, "plan": plan.rationale},
            )
        if action is PlannedAction.STOP_UNCERTAIN:
            return RouteDecision(
                AgentRoute.REPORT,
                "uncertain with missing evidence; generate report",
                metadata={"gap_kind": plan.gap_kind.value, "plan": plan.rationale},
            )

        if action is PlannedAction.PARSE_OR_INDEX:
            if history.count(AgentRoute.SOURCE_ANALYSIS.value) >= 1:
                # parsing already ran; re-running the same engine adds no new
                # evidence, so fall back to the bounded legacy decision.
                return self._legacy_after_analysis(task, context, history, plan)
            return RouteDecision(
                AgentRoute.SOURCE_ANALYSIS,
                "parse_or_index required for concrete location",
                metadata={"gap_kind": plan.gap_kind.value, "plan": plan.rationale},
            )

        if action is PlannedAction.GUARD_RECHECK:
            if history.count(AgentRoute.SOURCE_ANALYSIS.value) >= 1:
                # the current pass already produced a candidate; re-running
                # source analysis cannot manufacture a new guard/call-path
                # fact, so hand the gap to a requested fuzz or verification
                # instead of looping the same engine.
                return self._legacy_after_analysis(task, context, history, plan)
            return RouteDecision(
                AgentRoute.SOURCE_ANALYSIS,
                "guard_recheck required before verification",
                metadata={"gap_kind": plan.gap_kind.value, "plan": plan.rationale},
            )

        if action is PlannedAction.INDEPENDENT_REVIEW:
            return RouteDecision(
                AgentRoute.REVIEWER,
                "independent review required for engine disagreement",
                metadata={"gap_kind": plan.gap_kind.value, "plan": plan.rationale},
            )

        if action is PlannedAction.BOUNDED_FUZZ:
            if AgentRoute.FUZZ.value in history:
                return RouteDecision(
                    AgentRoute.VERIFICATION,
                    "fuzz already ran; proceed to verification",
                    metadata={"gap_kind": plan.gap_kind.value, "plan": plan.rationale},
                )
            return RouteDecision(
                AgentRoute.FUZZ,
                "bounded fuzz requested by evidence-gap planner",
                metadata={
                    "gap_kind": plan.gap_kind.value,
                    "plan": plan.rationale,
                    "budget_seconds": (
                        plan.binding.budget_seconds if plan.binding else 300
                    ),
                    "permission_required": (
                        plan.binding.permission_required if plan.binding else "dynamic_run"
                    ),
                },
            )

        # verification and everything else
        return RouteDecision(
            AgentRoute.VERIFICATION,
            plan.rationale or "evidence sufficient; verify candidate",
            metadata={"gap_kind": plan.gap_kind.value, "plan": plan.rationale},
        )

    def _legacy_after_analysis(
        self,
        task: Task,
        context: AnalysisContext,
        history: list[str],
        plan: PlanDecision,
    ) -> RouteDecision:
        """Fall back to the bounded V0.2 post-analysis decision.

        Used when an evidence-gap recheck cannot add new facts by re-running
        the same analysis engine: honor an authorized fuzz request first,
        then route findings to independent verification, otherwise report.
        The triggering gap stays visible in route metadata for tracing.
        """

        gap_metadata = {"gap_kind": plan.gap_kind.value, "plan": plan.rationale}
        if not context.findings:
            return RouteDecision(
                AgentRoute.REPORT,
                "analysis completed without findings",
                metadata=gap_metadata,
            )
        if self._fuzz_requested(task, context) and AgentRoute.FUZZ.value not in history:
            return RouteDecision(
                AgentRoute.FUZZ,
                "authorized dynamic evidence was requested",
                metadata=gap_metadata,
            )
        return RouteDecision(
            AgentRoute.VERIFICATION,
            "candidate requires independent verification",
            metadata=gap_metadata,
        )

    @staticmethod
    def _protected_binary(task: Task) -> bool:
        if task.target.target_type is not TargetType.BINARY:
            return False
        metadata = task.target.metadata
        return str(metadata.get("test_lab_category", "")).casefold() in {
            "packed_binary",
            "obfuscated_binary",
        } or str(task.target.file_format or "").casefold() in {"dex", "apk"}

    def _available(self, route: AgentRoute, task: Task) -> bool:
        if self.available_routes is not None and route.value not in self.available_routes:
            return False
        if self.profile_hint_reader is not None:
            allowed = self.profile_hint_reader(task)
            if allowed is not None and route.value not in allowed:
                return False
        return True

    @staticmethod
    def _fuzz_requested(task: Task, context: AnalysisContext) -> bool:
        authorized = bool(task.target.metadata.get("fuzz_authorized", False))
        suitable = task.target.target_type in {TargetType.SOURCE, TargetType.PROJECT, TargetType.BINARY}
        planned = any(
            message.message_type.value == "plan"
            and "fuzz.execute" in message.payload.get("requested_capabilities", [])
            for message in context.messages
        )
        return authorized and suitable and planned
