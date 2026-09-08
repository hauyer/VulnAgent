from dataclasses import replace

import pytest

from vulnagent.agent_runtime import (
    AgentRoute,
    CapabilityName,
    ToolRegistry,
    ToolSpec,
)
from vulnagent.agent_runtime.errors import (
    ToolRegistrationError,
)
from vulnagent.bootstrap import (
    build_application,
    build_mock_application,
    build_mock_capabilities,
    build_tool_registry,
)
from vulnagent.contracts import (
    ProjectInput,
    SourceAnalysisResult,
)


class FakeSourceParser:
    """Protocol-compatible async replacement parser."""

    async def analyze(
        self,
        request: ProjectInput,
    ) -> SourceAnalysisResult:
        return SourceAnalysisResult(
            task_id=request.task_id,
            target_id=request.target_id,
            project_path=request.project_path,
            languages=["fake"],
            files=[],
            symbols=[],
            dependencies=[],
            call_graph={},
            metadata={
                "fake": True,
            },
        )


class InvalidSourceParser:
    """Intentionally missing SourceParser.analyze."""


class SyncSourceParser:
    """Incorrect synchronous SourceParser implementation."""

    def analyze(
        self,
        request: ProjectInput,
    ) -> SourceAnalysisResult:
        return SourceAnalysisResult(
            task_id=request.task_id,
            target_id=request.target_id,
            project_path=request.project_path,
            languages=["sync"],
            files=[],
            symbols=[],
            dependencies=[],
            call_graph={},
            metadata={
                "sync": True,
            },
        )


def test_mock_application_registers_all_runtime_agents() -> None:
    services = build_mock_application()

    assert services.agent_registry.list_agents() == [
        AgentRoute.PLANNER.value,
        AgentRoute.SOURCE_ANALYSIS.value,
        AgentRoute.BINARY_ANALYSIS.value,
        AgentRoute.FUZZ.value,
        AgentRoute.VERIFICATION.value,
        AgentRoute.REVIEWER.value,
        AgentRoute.REPORT.value,
    ]


def test_mock_application_registers_expected_capabilities() -> None:
    services = build_mock_application()

    assert services.tool_registry.names() == [
        CapabilityName.SOURCE_PARSE.value,
        CapabilityName.SOURCE_AUDIT.value,
        CapabilityName.BINARY_INSPECT.value,
        CapabilityName.FUZZ_EXECUTE.value,
        CapabilityName.VERIFICATION_VERIFY.value,
        CapabilityName.REPORT_GENERATE.value,
    ]


def test_runtime_receives_same_tool_registry_instance() -> None:
    services = build_mock_application()

    assert (
        services.runtime.tool_registry
        is services.tool_registry
    )


def test_runtime_policy_is_built_from_settings() -> None:
    services = build_mock_application()

    assert (
        services.runtime_policy.max_agent_steps
        == services.settings.max_agent_steps
    )

    assert (
        services.runtime_policy.max_route_repeats
        == services.settings.max_route_repeats
    )

    assert (
        services.runtime_policy.max_analysis_retries
        == services.settings.max_analysis_retries
    )


def test_capability_can_replace_mock_without_runtime_change() -> None:
    fake_parser = FakeSourceParser()

    capabilities = replace(
        build_mock_capabilities(),
        source_parser=fake_parser,
    )

    services = build_application(
        capabilities
    )

    source_agent = services.agent_registry.get(
        AgentRoute.SOURCE_ANALYSIS.value
    )

    assert (
        services.capabilities.source_parser
        is fake_parser
    )

    assert getattr(
        source_agent,
        "parser",
    ) is fake_parser

    tool = services.tool_registry.get(
        CapabilityName.SOURCE_PARSE.value
    )

    assert (
        tool.adapter.__self__
        is fake_parser
    )


def test_missing_capability_method_fails_fast() -> None:
    """Capability without required method must fail during composition."""

    capabilities = build_mock_capabilities()

    with pytest.raises(
        TypeError,
        match=(
            "source_parser.*"
            "missing callable.*"
            "analyze"
        ),
    ):
        replace(
            capabilities,
            source_parser=InvalidSourceParser(),
        )


def test_synchronous_capability_method_fails_fast() -> None:
    """Synchronous implementation must not satisfy an async Protocol."""

    capabilities = build_mock_capabilities()

    with pytest.raises(
        TypeError,
        match=(
            "source_parser.*"
            "analyze.*"
            "must be async"
        ),
    ):
        replace(
            capabilities,
            source_parser=SyncSourceParser(),
        )


def test_empty_custom_tool_registry_fails_fast() -> None:
    """Injected registries must contain all mandatory capabilities."""

    capabilities = build_mock_capabilities()

    custom_registry = ToolRegistry()

    with pytest.raises(
        ToolRegistrationError,
        match="Missing required application tools",
    ) as exc_info:
        build_application(
            capabilities,
            tool_registry=custom_registry,
        )

    message = str(
        exc_info.value
    )

    assert (
        CapabilityName.SOURCE_PARSE.value
        in message
    )

    assert (
        CapabilityName.SOURCE_AUDIT.value
        in message
    )

    assert (
        CapabilityName.BINARY_INSPECT.value
        in message
    )

    assert (
        CapabilityName.FUZZ_EXECUTE.value
        in message
    )

    assert (
        CapabilityName.VERIFICATION_VERIFY.value
        in message
    )

    assert (
        CapabilityName.REPORT_GENERATE.value
        in message
    )


def test_complete_custom_tool_registry_is_accepted() -> None:
    """A complete externally supplied registry must remain injectable."""

    capabilities = build_mock_capabilities()

    custom_registry = build_tool_registry(
        capabilities
    )

    services = build_application(
        capabilities,
        tool_registry=custom_registry,
    )

    assert (
        services.tool_registry
        is custom_registry
    )

    assert (
        services.runtime.tool_registry
        is custom_registry
    )


def test_custom_registry_is_validated_before_runtime_creation() -> None:
    """Invalid external registry must fail at Composition Root."""

    capabilities = build_mock_capabilities()

    custom_registry = ToolRegistry()

    with pytest.raises(
        ToolRegistrationError,
    ):
        build_application(
            capabilities,
            tool_registry=custom_registry,
        )
def test_partially_complete_custom_registry_reports_only_missing_tools() -> None:
    capabilities = build_mock_capabilities()

    custom_registry = ToolRegistry()

    custom_registry.register(
        ToolSpec(
            name=CapabilityName.SOURCE_PARSE.value,
            description="Parse source project structure",
            adapter=capabilities.source_parser.analyze,
            owner="P2",
            capability_type="source",
        )
    )

    with pytest.raises(
        ToolRegistrationError,
        match="Missing required application tools",
    ) as exc_info:
        build_application(
            capabilities,
            tool_registry=custom_registry,
        )

    message = str(
        exc_info.value
    )

    assert (
        CapabilityName.SOURCE_PARSE.value
        not in message
    )

    assert (
        CapabilityName.SOURCE_AUDIT.value
        in message
    )

    assert (
        CapabilityName.BINARY_INSPECT.value
        in message
    )


