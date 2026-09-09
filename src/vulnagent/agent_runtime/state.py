"""Typed transient state used only by the agent graph."""

from typing import Any, TypedDict

from vulnagent.contracts import AgentMessage


class RuntimeState(TypedDict):
    """Minimal routing state; business results remain in ``AnalysisContext``."""

    task_id: str
    current_agent: str | None
    next_agent: str | None
    step_count: int
    route_history: list[str]
    messages: list[AgentMessage]
    pending_actions: list[str]
    completed_agents: list[str]
    runtime_metadata: dict[str, Any]


def initial_runtime_state(task_id: str) -> RuntimeState:
    """Create isolated state for one graph invocation."""
    return RuntimeState(
        task_id=task_id,
        current_agent=None,
        next_agent=None,
        step_count=0,
        route_history=[],
        messages=[],
        pending_actions=[],
        completed_agents=[],
        runtime_metadata={},
    )
