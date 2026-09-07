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

    def resolve(self, requested: AgentRoute | str | None, history: list[str]) -> RouteDecision:
        """Return a legal route, using a deterministic report/finish fallback."""
        try:
            route = requested if isinstance(requested, AgentRoute) else AgentRoute(requested)
        except (TypeError, ValueError):
            return self._fallback(history, "invalid supervisor route")

        if route is AgentRoute.FINISH:
            return RouteDecision(route=route, reason="workflow complete")
        if len(history) >= self.policy.max_agent_steps:
            return self._fallback(history, "agent step limit reached")
        if history.count(route.value) >= self.policy.max_route_repeats:
            return self._fallback(history, f"route repeat limit reached: {route.value}")
        return RouteDecision(route=route, reason="validated supervisor route")

    @staticmethod
    def _fallback(history: list[str], reason: str) -> RouteDecision:
        route = AgentRoute.FINISH if AgentRoute.REPORT.value in history else AgentRoute.REPORT
        return RouteDecision(route=route, reason=reason, fallback_used=True)
