"""VulnAgent application composition root.

All concrete implementations are assembled here.

Business modules must depend on public Contracts/Protocols and must not
construct concrete analyzers, fuzzers, verifiers, report generators,
external tools, or model providers by themselves.

The composition root is intentionally explicit.  VulnAgent does not use
a reflection-heavy dependency injection framework because explicit
construction is easier to test, review and reproduce.
"""

from dataclasses import dataclass
from typing import cast

from vulnagent.agent_runtime import (
    AgentRoute,
    AgentRuntime,
    CapabilityName,
    RuntimePolicy,
    ToolRegistry,
    ToolSpec,
)
from vulnagent.agent_runtime.errors import (
    ToolRegistrationError,
)
from vulnagent.agents import (
    BinaryAnalysisAgent,
    FuzzAgent,
    PlannerAgent,
    ReportAgent,
    ReviewerAgent,
    SourceAuditAgent,
    VerificationAgent,
)
from vulnagent.agents.registry import AgentRegistry
from vulnagent.analyzers.binary.reverse import (
    MockBinaryReverseAnalyzer,
)
from vulnagent.analyzers.source.audit import (
    MockSourceAuditor,
)
from vulnagent.analyzers.source.parser import (
    MockSourceParser,
)
from vulnagent.contracts import (
    EvidenceRepository,
    TaskRepository,
)
from vulnagent.core.dependencies import CapabilityBundle
from vulnagent.core.event_bus import EventBus
from vulnagent.core.orchestrator import Orchestrator
from vulnagent.core.task_manager import (
    InMemoryTaskManager,
)
from vulnagent.evidence.store import (
    InMemoryEvidenceStore,
)
from vulnagent.fuzz.mock import MockFuzzEngine
from vulnagent.llm.base import BaseLLM
from vulnagent.llm.router import LLMRouter
from vulnagent.report.generator import (
    MockReportGenerator,
)
from vulnagent.settings import (
    Settings,
    get_settings,
)
from vulnagent.verification.verifier import (
    MockVerifier,
)


@dataclass(
    frozen=True,
    slots=True,
)
class ApplicationServices:
    """Fully composed process-local VulnAgent service graph."""

    settings: Settings

    task_manager: TaskRepository
    evidence_store: EvidenceRepository
    event_bus: EventBus

    capabilities: CapabilityBundle

    agent_registry: AgentRegistry
    tool_registry: ToolRegistry

    llm: BaseLLM

    runtime_policy: RuntimePolicy
    runtime: AgentRuntime

    orchestrator: Orchestrator


def build_mock_capabilities() -> CapabilityBundle:
    """Build the default safe and non-destructive V0.2 capabilities."""

    return CapabilityBundle(
        source_parser=MockSourceParser(),
        source_auditor=MockSourceAuditor(),
        binary_analyzer=MockBinaryReverseAnalyzer(),
        fuzz_engine=MockFuzzEngine(),
        verifier=MockVerifier(),
        report_generator=MockReportGenerator(),
    )


def build_tool_registry(
    capabilities: CapabilityBundle,
) -> ToolRegistry:
    """Build the single provider-neutral logical capability registry."""

    registry = ToolRegistry()

    registry.register_many(
        [
            ToolSpec(
                name=CapabilityName.SOURCE_PARSE.value,
                description="Parse source project structure",
                adapter=capabilities.source_parser.analyze,
                owner="P2",
                capability_type="source",
            ),
            ToolSpec(
                name=CapabilityName.SOURCE_AUDIT.value,
                description="Audit parsed source structure",
                adapter=capabilities.source_auditor.audit,
                owner="P3",
                capability_type="source",
            ),
            ToolSpec(
                name=CapabilityName.BINARY_INSPECT.value,
                description="Inspect a binary statically",
                adapter=capabilities.binary_analyzer.analyze,
                owner="P4",
                capability_type="binary",
            ),
            ToolSpec(
                name=CapabilityName.FUZZ_EXECUTE.value,
                description=(
                    "Run an authorization-gated fuzz capability"
                ),
                adapter=capabilities.fuzz_engine.run,
                owner="P6",
                capability_type="dynamic",
            ),
            ToolSpec(
                name=CapabilityName.VERIFICATION_VERIFY.value,
                description=(
                    "Independently verify one vulnerability candidate"
                ),
                adapter=capabilities.verifier.verify,
                owner="P7",
                capability_type="verification",
            ),
            ToolSpec(
                name=CapabilityName.REPORT_GENERATE.value,
                description="Generate a structured VulnAgent report",
                adapter=capabilities.report_generator.generate,
                owner="P9",
                capability_type="report",
            ),
        ]
    )

    return registry
def validate_tool_registry(
    registry: ToolRegistry,
) -> None:
    """Ensure all mandatory VulnAgent capabilities are registered.

    ``ToolRegistry`` may be supplied externally through dependency
    injection.  A custom registry must therefore satisfy the same
    minimum logical capability contract as the default registry.

    Validation happens during application composition so missing tools
    cannot survive until runtime execution.
    """

    missing = [
        capability.value
        for capability in CapabilityName
        if not registry.contains(
            capability.value
        )
    ]

    if missing:
        raise ToolRegistrationError(
            "Missing required application tools: "
            + ", ".join(missing)
        )

def build_agent_registry(
    capabilities: CapabilityBundle,
) -> AgentRegistry:
    """Build runtime agents from injected capability Protocols.

    Registry keys deliberately use AgentRoute values rather than
    BaseAgent.name.
    """

    registry = AgentRegistry()

    registry.register_many(
        {
            AgentRoute.PLANNER.value:
                PlannerAgent(),

            AgentRoute.SOURCE_ANALYSIS.value:
                SourceAuditAgent(
                    capabilities.source_parser,
                    capabilities.source_auditor,
                ),

            AgentRoute.BINARY_ANALYSIS.value:
                BinaryAnalysisAgent(
                    capabilities.binary_analyzer,
                ),

            AgentRoute.FUZZ.value:
                FuzzAgent(
                    capabilities.fuzz_engine,
                ),

            AgentRoute.VERIFICATION.value:
                VerificationAgent(
                    capabilities.verifier,
                ),

            AgentRoute.REVIEWER.value:
                ReviewerAgent(),

            AgentRoute.REPORT.value:
                ReportAgent(
                    capabilities.report_generator,
                ),
        }
    )

    return registry


def build_runtime_policy(
    settings: Settings,
) -> RuntimePolicy:
    """Build bounded runtime policy from application settings."""

    return RuntimePolicy(
        max_agent_steps=settings.max_agent_steps,
        max_route_repeats=settings.max_route_repeats,
        max_analysis_retries=settings.max_analysis_retries,
    )


def build_application(
    capabilities: CapabilityBundle,
    *,
    settings: Settings | None = None,
    task_manager: TaskRepository | None = None,
    evidence_store: EvidenceRepository | None = None,
    event_bus: EventBus | None = None,
    llm: BaseLLM | None = None,
    agent_registry: AgentRegistry | None = None,
    tool_registry: ToolRegistry | None = None,
    runtime_policy: RuntimePolicy | None = None,
) -> ApplicationServices:
    """Compose a complete VulnAgent application dependency graph.

    This is the primary dependency-injection boundary.

    Real implementations should be supplied here as public
    Protocol-compatible dependencies instead of being imported by
    AgentRuntime, Orchestrator or individual Agents.
    """

    resolved_settings = (
        settings
        if settings is not None
        else get_settings()
    )

    resolved_task_manager = (
        task_manager
        if task_manager is not None
        else InMemoryTaskManager()
    )

    resolved_evidence_store = (
        evidence_store
        if evidence_store is not None
        else InMemoryEvidenceStore()
    )

    resolved_event_bus = (
        event_bus
        if event_bus is not None
        else EventBus()
    )

    resolved_llm = (
        llm
        if llm is not None
        else LLMRouter().get(
            resolved_settings.llm_provider
        )
    )

    resolved_tool_registry = (
        tool_registry
        if tool_registry is not None
        else build_tool_registry(
            capabilities
        )
    )

    validate_tool_registry(
        resolved_tool_registry
    )

    resolved_agent_registry = (
        agent_registry
        if agent_registry is not None
        else build_agent_registry(
            capabilities
        )
    )
    resolved_agent_registry = (
        agent_registry
        if agent_registry is not None
        else build_agent_registry(
            capabilities
        )
    )

    resolved_runtime_policy = (
        runtime_policy
        if runtime_policy is not None
        else build_runtime_policy(
            resolved_settings
        )
    )

    runtime = AgentRuntime(
        resolved_agent_registry.as_mapping(),
        policy=resolved_runtime_policy,
        publish_event=resolved_event_bus.publish,
        tool_registry=resolved_tool_registry,
        llm=resolved_llm,
    )

    orchestrator = Orchestrator(
        resolved_task_manager,
        resolved_evidence_store,
        runtime,
        resolved_event_bus,
    )

    return ApplicationServices(
        settings=resolved_settings,
        task_manager=resolved_task_manager,
        evidence_store=resolved_evidence_store,
        event_bus=resolved_event_bus,
        capabilities=capabilities,
        agent_registry=resolved_agent_registry,
        tool_registry=resolved_tool_registry,
        llm=resolved_llm,
        runtime_policy=resolved_runtime_policy,
        runtime=runtime,
        orchestrator=orchestrator,
    )


def build_mock_application(
    *,
    settings: Settings | None = None,
) -> ApplicationServices:
    """Build the default safe V0.2 mock application."""

    return build_application(
        build_mock_capabilities(),
        settings=settings,
    )


def build_mock_services(
) -> tuple[
    InMemoryTaskManager,
    InMemoryEvidenceStore,
    Orchestrator,
]:
    """Backward-compatible V0.2 service builder.

    Existing API and integration tests still consume the historical
    ``(task_manager, evidence_store, orchestrator)`` tuple.

    Keep this wrapper until those callers are deliberately migrated to
    ``ApplicationServices``.
    """

    services = build_mock_application()

    return (
        cast(
            InMemoryTaskManager,
            services.task_manager,
        ),
        cast(
            InMemoryEvidenceStore,
            services.evidence_store,
        ),
        services.orchestrator,
    )