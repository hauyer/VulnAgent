from dataclasses import replace

import pytest

from vulnagent.agent_runtime import (
    AgentRoute,
    CapabilityName,
)
from vulnagent.bootstrap import (
    build_application,
    build_mock_application,
    build_mock_capabilities,
)
from vulnagent.contracts import (
    ProjectInput,
    SourceAnalysisResult,
)


class FakeSourceParser:
    """Protocol-compatible replacement parser used by DI tests."""

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

    assert (
        source_agent.parser
        is fake_parser
    )

    tool = services.tool_registry.get(
        CapabilityName.SOURCE_PARSE.value
    )

    assert (
        tool.adapter.__self__
        is fake_parser
    )


def test_invalid_capability_fails_during_composition() -> None:
    capabilities = build_mock_capabilities()

    with pytest.raises(
        TypeError,
        match="source_parser",
    ):
        replace(
            capabilities,
            source_parser=InvalidSourceParser(),
        )