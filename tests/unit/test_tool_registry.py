import pytest

from vulnagent.agent_runtime import (
    CapabilityName,
    ToolRegistry,
    ToolSpec,
)
from vulnagent.agent_runtime.errors import (
    ToolRegistrationError,
)


async def _adapter(
    value: int,
) -> int:
    return value + 1


def _tool(
    name: str,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        description="test capability",
        adapter=_adapter,
        owner="P1",
        capability_type="test",
    )


@pytest.mark.asyncio
async def test_register_and_resolve_tool() -> None:
    registry = ToolRegistry()

    registry.register(
        _tool(
            CapabilityName.SOURCE_PARSE.value
        )
    )

    tool = registry.get(
        CapabilityName.SOURCE_PARSE.value
    )

    assert await tool.adapter(1) == 2

    assert registry.names() == [
        "source.parse"
    ]

    assert "source.parse" in registry
    assert len(registry) == 1


def test_duplicate_tool_rejected() -> None:
    registry = ToolRegistry()

    registry.register(
        _tool("source.parse")
    )

    with pytest.raises(
        ToolRegistrationError,
        match="Tool already registered",
    ):
        registry.register(
            _tool("source.parse")
        )


def test_register_many_is_atomic() -> None:
    registry = ToolRegistry()

    registry.register(
        _tool("source.parse")
    )

    with pytest.raises(
        ToolRegistrationError,
        match="Tool already registered",
    ):
        registry.register_many(
            [
                _tool("source.parse"),
                _tool("source.audit"),
            ]
        )

    assert registry.names() == [
        "source.parse"
    ]


def test_duplicate_inside_batch_rejected() -> None:
    registry = ToolRegistry()

    with pytest.raises(
        ToolRegistrationError,
        match="Duplicate tool",
    ):
        registry.register_many(
            [
                _tool("source.parse"),
                _tool("source.parse"),
            ]
        )

    assert len(registry) == 0


def test_unknown_tool_rejected() -> None:
    registry = ToolRegistry()

    with pytest.raises(
        ToolRegistrationError,
        match="Unknown tool",
    ):
        registry.get(
            "source.parse"
        )


def test_invalid_logical_name_rejected() -> None:
    with pytest.raises(
        ToolRegistrationError,
        match="Invalid logical tool name",
    ):
        _tool(
            "source_parse"
        )


def test_tool_spec_rejects_synchronous_adapter() -> None:
    def sync_adapter(
        value: int,
    ) -> int:
        return value + 1

    with pytest.raises(
        ToolRegistrationError,
        match="must be asynchronous",
    ):
        ToolSpec(
            name="source.parse",
            description="sync adapter",
            adapter=sync_adapter,  # type: ignore[arg-type]
            owner="P1",
            capability_type="test",
        )


def test_tool_spec_accepts_async_callable_object() -> None:
    class AsyncAdapter:
        async def __call__(
            self,
            value: int,
        ) -> int:
            return value + 1

    tool = ToolSpec(
        name="source.parse",
        description="async callable adapter",
        adapter=AsyncAdapter(),
        owner="P1",
        capability_type="test",
    )

    assert tool.name == "source.parse"


def test_require_multiple_tools() -> None:
    registry = ToolRegistry()

    registry.register_many(
        [
            _tool("source.parse"),
            _tool("source.audit"),
        ]
    )

    tools = registry.require(
        [
            "source.parse",
            "source.audit",
        ]
    )

    assert [
        tool.name
        for tool in tools
    ] == [
        "source.parse",
        "source.audit",
    ]
