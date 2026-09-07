"""Optional ReAct-style tool binding built on VulnAgent capability adapters."""

from typing import Any

from vulnagent.agents.base import BaseAgent

from .tool_registry import ToolRegistry


class ToolEnabledAgent(BaseAgent):
    """BaseAgent extension that exposes an allow-list of logical tools.

    Subclasses still implement the canonical ``run(task, context)`` method. This
    adapter only provides controlled invocation and never exposes concrete SDKs.
    """

    def __init__(self, tool_registry: ToolRegistry, tool_names: list[str]) -> None:
        self._tool_registry = tool_registry
        self._tool_names = frozenset(tool_names)
        for name in self._tool_names:
            tool_registry.get(name)

    @property
    def tool_names(self) -> tuple[str, ...]:
        """Return the agent's immutable logical tool allow-list."""
        return tuple(sorted(self._tool_names))

    async def invoke_tool(self, name: str, *args: Any, **kwargs: Any) -> Any:
        """Invoke an injected capability adapter if it is bound to this agent."""
        if name not in self._tool_names:
            raise PermissionError(f"Tool is not bound to agent {self.name}: {name}")
        return await self._tool_registry.get(name).adapter(*args, **kwargs)
