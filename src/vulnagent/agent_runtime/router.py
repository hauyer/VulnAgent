"""Validated route vocabulary and deterministic fallback rules."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .policies import RuntimePolicy


class AgentRoute(str, Enum):
    """Only destinations the V0.2 runtime may execute."""

    PLANNER = "planner"
    SOURCE_ANALYSIS = "source_analysis"
    BINARY_ANALYSIS = "binary_analysis"
    FUZZ = "fuzz"
    VERIFICATION = "verification"
    REVIEWER = "reviewer"
    REPORT = "report"
    FINISH = "finish"


@dataclass(frozen=True, slots=True)
class RouteDecision:
    """A validated supervisor decision safe for graph dispatch."""

    route: AgentRoute
    reason: str
    fallback_used: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentRouter:
    """Validate supervisor output and stop repeated or invalid routes safely."""

    def __init__(self, policy: RuntimePolicy | None = None) -> None:
        self.policy = policy or RuntimePolicy()

    def resolve(
        self,
        requested: AgentRoute | str | None,
        history: list[str],
    ) -> RouteDecision:
        """Return a legal and bounded route.

        ``max_agent_steps`` is treated as a hard upper bound on executed
        agent nodes. When only one step remains, that final slot is
        reserved for the report fallback.
        """

        try:
            route = (
                requested
                if isinstance(requested, AgentRoute)
                else AgentRoute(requested)
            )
        except (TypeError, ValueError):
            return self._fallback(
                history,
                "invalid supervisor route",
            )

        # FINISH is not an executable Agent step.
        if route is AgentRoute.FINISH:
            return RouteDecision(
                route=AgentRoute.FINISH,
                reason="workflow complete",
            )

        executed_steps = len(history)

        # No executable Agent may run beyond the hard limit.
        if executed_steps >= self.policy.max_agent_steps:
            return self._fallback(
                history,
                "agent step limit reached",
            )

        # A route may execute at most max_route_repeats times.
        if history.count(route.value) >= self.policy.max_route_repeats:
            return self._fallback(
                history,
                f"route repeat limit reached: {route.value}",
            )

        # Reserve the final executable slot for a safe report.
        if (
            executed_steps == self.policy.max_agent_steps - 1
            and route is not AgentRoute.REPORT
        ):
            return self._fallback(
                history,
                "agent step limit approaching; "
                "reserved final step for report",
            )

        return RouteDecision(
            route=route,
            reason="validated supervisor route",
        )

    def _fallback(
        self,
        history: list[str],
        reason: str,
    ) -> RouteDecision:
        """Return REPORT when still possible, otherwise terminate safely."""

        # If Report has already run, there is no reason to execute it again.
        if AgentRoute.REPORT.value in history:
            route = AgentRoute.FINISH

        # If the Agent execution budget is already exhausted,
        # executing Report would violate max_agent_steps.
        elif len(history) >= self.policy.max_agent_steps:
            route = AgentRoute.FINISH

        else:
            route = AgentRoute.REPORT

        return RouteDecision(
            route=route,
            reason=reason,
            fallback_used=True,
        )