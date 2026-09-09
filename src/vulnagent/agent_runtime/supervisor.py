"""Deterministic V0.2 supervisor for context-aware agent selection."""

from vulnagent.contracts import AnalysisContext, TargetType, Task

from .router import AgentRoute, RouteDecision
from .state import RuntimeState


class Supervisor:
    """Choose the next specialized agent without executing capabilities."""

    def __init__(self, max_analysis_retries: int = 1) -> None:
        if max_analysis_retries < 0:
            raise ValueError(
                "max_analysis_retries cannot be negative"
            )

        self.max_analysis_retries = max_analysis_retries
    def decide(self, task: Task, context: AnalysisContext, state: RuntimeState) -> RouteDecision:
        """Select a structured route from task type and accumulated results."""
        current = state["current_agent"]
        history = state["route_history"]
        if current is None:
            return RouteDecision(AgentRoute.PLANNER, "initialize a structured plan")
        if current == AgentRoute.PLANNER.value:
            route = AgentRoute.BINARY_ANALYSIS if task.target.target_type is TargetType.BINARY else AgentRoute.SOURCE_ANALYSIS
            return RouteDecision(route, "route by target type")
        if current in {AgentRoute.SOURCE_ANALYSIS.value, AgentRoute.BINARY_ANALYSIS.value}:
            if not context.findings:
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
