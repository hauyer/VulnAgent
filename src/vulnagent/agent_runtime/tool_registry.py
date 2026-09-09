"""Registry of provider-neutral logical capabilities.

``ToolRegistry`` is the single runtime registry for logical tools and
capabilities.

It stores stable logical names such as ``source.parse`` instead of
concrete implementation names such as ``tree_sitter_python`` or
``semgrep``.

Concrete implementations must be injected by ``bootstrap.py``.
"""

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from inspect import iscoroutinefunction
import re
from typing import Any

from .errors import ToolRegistrationError


ToolCallable = Callable[..., Awaitable[Any]]


_LOGICAL_CAPABILITY_PATTERN = re.compile(
    r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$"
)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Metadata and adapter for one logical capability."""

    name: str
    description: str
    adapter: ToolCallable
    owner: str
    capability_type: str

    def __post_init__(self) -> None:
        """Validate capability metadata during application bootstrap."""

        if not isinstance(self.name, str):
            raise ToolRegistrationError(
                "Tool name must be a string"
            )

        if not _LOGICAL_CAPABILITY_PATTERN.fullmatch(
            self.name
        ):
            raise ToolRegistrationError(
                "Invalid logical tool name: "
                f"{self.name!r}. "
                "Expected a name such as 'source.parse'."
            )

        if not isinstance(self.description, str):
            raise ToolRegistrationError(
                f"Tool description must be a string: {self.name}"
            )

        if not self.description.strip():
            raise ToolRegistrationError(
                f"Tool description cannot be empty: {self.name}"
            )

        if not callable(self.adapter):
            raise ToolRegistrationError(
                f"Tool adapter is not callable: {self.name}"
            )

        adapter_call = getattr(
            self.adapter,
            "__call__",
            None,
        )
        if not (
            iscoroutinefunction(self.adapter)
            or iscoroutinefunction(adapter_call)
        ):
            raise ToolRegistrationError(
                f"Tool adapter must be asynchronous: {self.name}"
            )

        if not isinstance(self.owner, str) or not self.owner.strip():
            raise ToolRegistrationError(
                f"Tool owner cannot be empty: {self.name}"
            )

        if (
            not isinstance(self.capability_type, str)
            or not self.capability_type.strip()
        ):
            raise ToolRegistrationError(
                "Tool capability_type cannot be empty: "
                f"{self.name}"
            )


class ToolRegistry:
    """Resolve logical capabilities without exposing concrete providers."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(
        self,
        tool: ToolSpec,
    ) -> None:
        """Register one uniquely named logical capability."""

        if tool.name in self._tools:
            raise ToolRegistrationError(
                f"Tool already registered: {tool.name}"
            )

        self._tools[tool.name] = tool

    def register_many(
        self,
        tools: Iterable[ToolSpec],
    ) -> None:
        """Atomically register several logical capabilities.

        The whole batch is checked before the internal mapping is
        modified, preventing partially registered application state.
        """

        pending = list(tools)

        existing_names = set(self._tools)
        batch_names: set[str] = set()

        for tool in pending:
            if tool.name in existing_names:
                raise ToolRegistrationError(
                    f"Tool already registered: {tool.name}"
                )

            if tool.name in batch_names:
                raise ToolRegistrationError(
                    "Duplicate tool in registration batch: "
                    f"{tool.name}"
                )

            batch_names.add(tool.name)

        for tool in pending:
            self._tools[tool.name] = tool

    def get(
        self,
        name: str,
    ) -> ToolSpec:
        """Resolve one registered logical capability."""

        try:
            return self._tools[name]

        except KeyError as exc:
            raise ToolRegistrationError(
                f"Unknown tool: {name}"
            ) from exc

    def require(
        self,
        names: Iterable[str],
    ) -> list[ToolSpec]:
        """Resolve all required logical capabilities.

        Raises immediately when any capability is unavailable.
        """

        return [
            self.get(name)
            for name in names
        ]

    def contains(
        self,
        name: str,
    ) -> bool:
        """Return whether the capability is registered."""

        return name in self._tools

    def names(
        self,
    ) -> list[str]:
        """Return logical capability names in registration order."""

        return list(self._tools)

    def list_tools(
        self,
    ) -> list[ToolSpec]:
        """Return registered ToolSpec objects in registration order."""

        return list(self._tools.values())

    def as_mapping(
        self,
    ) -> dict[str, ToolSpec]:
        """Return a defensive copy of the internal registry."""

        return dict(self._tools)

    def __contains__(
        self,
        name: object,
    ) -> bool:
        """Support ``name in registry``."""

        return (
            isinstance(name, str)
            and name in self._tools
        )

    def __len__(
        self,
    ) -> int:
        """Return the number of registered capabilities."""

        return len(self._tools)
