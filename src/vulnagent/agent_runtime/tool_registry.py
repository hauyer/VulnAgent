"""Registry of logical capability tools exposed to tool-enabled agents."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from .errors import ToolRegistrationError

ToolCallable = Callable[..., Awaitable[Any]]


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Metadata and adapter for one logical, provider-neutral capability."""

    name: str
    description: str
    adapter: ToolCallable
    owner: str
    capability_type: str


class ToolRegistry:
    """Resolve logical tools without exposing concrete vendors to agents."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, tool: ToolSpec) -> None:
        """Register a uniquely named logical tool."""
        if tool.name in self._tools:
            raise ToolRegistrationError(f"Tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolSpec:
        """Resolve a tool or raise a normalized runtime error."""
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolRegistrationError(f"Unknown tool: {name}") from exc

    def list_tools(self) -> list[ToolSpec]:
        """Return tools in deterministic registration order."""
        return list(self._tools.values())
