from dataclasses import replace

import pytest

from vulnagent.agent_runtime import (
    AgentRoute,
    CapabilityName,
    RuntimePolicy,
    ToolRegistry,
    ToolSpec,
)
from vulnagent.agent_runtime.errors import (
    ToolRegistrationError,
)
from vulnagent.bootstrap import (
    build_application,
    build_agent_registry,
    build_mock_application,
    build_mock_capabilities,
    build_tool_registry,
)
from vulnagent.contracts import (
    BinaryAnalysisRequest,
    BinaryAnalysisResult,
    FuzzRequest,
    FuzzResult,
    ProjectInput,
    ReportRequest,
    ReportResult,
    SourceAnalysisResult,
    Target,
    TargetType,
    Task,
    VerificationContext,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityStatus,
)
from vulnagent.agents.planner_agent import PlannerAgent
from vulnagent.agents.registry import AgentRegistry
from vulnagent.core.event_bus import EventBus
from vulnagent.core.task_manager import InMemoryTaskManager
from vulnagent.evidence.store import InMemoryEvidenceStore
from vulnagent.llm.mock import MockLLM


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


class FakeSourceAuditor:
    async def audit(
        self,
        result: SourceAnalysisResult,
    ) -> list[VulnerabilityCandidate]:
        return []


class FakeBinaryAnalyzer:
    async def analyze(
        self,
        request: BinaryAnalysisRequest,
    ) -> BinaryAnalysisResult:
        return BinaryAnalysisResult(
            task_id=request.task_id,
            target_id=request.target_id,
            path=request.path,
            metadata={"fake": True},
        )


class FakeBinaryFeatureAnalyzer:
    async def inspect(self, result: BinaryAnalysisResult) -> dict[str, object]:
        return {"target_id": result.target_id, "fake": True}


class FakeFuzzEngine:
    async def run(self, request: FuzzRequest) -> FuzzResult:
        return FuzzResult(
            task_id=request.task_id,
            target_id=request.target_id,
            metadata={"fake": True},
        )


class FakeVerifier:
    async def verify(
        self,
        candidate: VulnerabilityCandidate,
        context: VerificationContext,
    ) -> VerificationResult:
        return VerificationResult(
            vulnerability_id=candidate.vulnerability_id,
            task_id=candidate.task_id,
            status=VulnerabilityStatus.UNCERTAIN,
            confidence=candidate.confidence,
            rationale="fake verification",
        )


class FakeReportGenerator:
    async def generate(self, request: ReportRequest) -> ReportResult:
        return ReportResult(
            task_id=request.task.task_id,
            content={"fake": True},
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
        CapabilityName.BINARY_LOGIC.value,
        CapabilityName.BINARY_OBFUSCATION.value,
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


def test_custom_dependency_identity_is_preserved() -> None:
    capabilities = build_mock_capabilities()
    task_manager = InMemoryTaskManager()
    evidence_store = InMemoryEvidenceStore()
    event_bus = EventBus()
    agent_registry = build_agent_registry(capabilities)
    tool_registry = build_tool_registry(capabilities)
    runtime_policy = RuntimePolicy(
        max_agent_steps=9,
        max_route_repeats=3,
        max_analysis_retries=0,
    )
    llm = MockLLM()

    services = build_application(
        capabilities,
        task_manager=task_manager,
        evidence_store=evidence_store,
        event_bus=event_bus,
        agent_registry=agent_registry,
        tool_registry=tool_registry,
        runtime_policy=runtime_policy,
        llm=llm,
    )

    assert services.task_manager is task_manager
    assert services.evidence_store is evidence_store
    assert services.event_bus is event_bus
    assert services.agent_registry is agent_registry
    assert services.tool_registry is tool_registry
    assert services.runtime_policy is runtime_policy
    assert services.llm is llm


def test_all_capabilities_are_replaceable_at_composition_root() -> None:
    parser = FakeSourceParser()
    auditor = FakeSourceAuditor()
    binary = FakeBinaryAnalyzer()
    logic = FakeBinaryFeatureAnalyzer()
    obfuscation = FakeBinaryFeatureAnalyzer()
    fuzz = FakeFuzzEngine()
    verifier = FakeVerifier()
    report = FakeReportGenerator()
    capabilities = type(build_mock_capabilities())(
        source_parser=parser,
        source_auditor=auditor,
        binary_analyzer=binary,
        binary_logic_analyzer=logic,
        binary_obfuscation_analyzer=obfuscation,
        fuzz_engine=fuzz,
        verifier=verifier,
        report_generator=report,
    )

    services = build_application(capabilities)

    expected_bindings = {
        CapabilityName.SOURCE_PARSE.value: parser,
        CapabilityName.SOURCE_AUDIT.value: auditor,
        CapabilityName.BINARY_INSPECT.value: binary,
        CapabilityName.BINARY_LOGIC.value: logic,
        CapabilityName.BINARY_OBFUSCATION.value: obfuscation,
        CapabilityName.FUZZ_EXECUTE.value: fuzz,
        CapabilityName.VERIFICATION_VERIFY.value: verifier,
        CapabilityName.REPORT_GENERATE.value: report,
    }
    for name, dependency in expected_bindings.items():
        assert services.tool_registry.get(name).adapter.__self__ is dependency

    assert services.runtime.tool_registry is services.tool_registry
    assert services.orchestrator.runtime is services.runtime


def test_agent_registry_rejects_non_base_agent() -> None:
    registry = AgentRegistry()

    with pytest.raises(TypeError, match="inherit BaseAgent"):
        registry.register(object())  # type: ignore[arg-type]


def test_missing_runtime_agent_fails_during_composition() -> None:
    capabilities = build_mock_capabilities()
    registry = AgentRegistry()
    registry.register(PlannerAgent(), key=AgentRoute.PLANNER.value)

    with pytest.raises(ValueError, match="Missing runtime agents"):
        build_application(capabilities, agent_registry=registry)

