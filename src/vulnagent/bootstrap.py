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
from pathlib import Path
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
    CodeAuditAgent,
    CodeDeobfuscationAgent,
    FuzzAgent,
    PlannerAgent,
    ProgramRestorationAgent,
    ReportAgent,
    ReviewerAgent,
    SourceAuditAgent,
    VerificationAgent,
)
from vulnagent.agents.registry import AgentRegistry
from vulnagent.analyzers.binary.reverse import (
    BinaryReverseWorkflow,
    MockBinaryReverseAnalyzer,
    Radare2Adapter,
    StaticBinaryReverseAnalyzer,
    UpxAdapter,
)
from vulnagent.analyzers.binary.deobfuscation import (
    SemanticRecoveryEnhancer,
    StaticDeobfuscationEngine,
)
from vulnagent.analyzers.binary.restoration import ProgramRestorationEngine
from vulnagent.analyzers.binary.logic import LogicAnalyzer, MockLogicAnalyzer
from vulnagent.analyzers.binary.obfuscation import (
    MockObfuscationAnalyzer,
    ObfuscationAnalyzer,
)
from vulnagent.analyzers.source.audit import (
    MockSourceAuditor,
    MultiLanguageSourceAuditor,
)
from vulnagent.analyzers.source.parser import (
    MockSourceParser,
    SourceProjectParser,
)
from vulnagent.contracts import (
    EvidenceRepository,
    TaskRepository,
)
from vulnagent.core.dependencies import CapabilityBundle
from vulnagent.core.context_store import ContextRepository, InMemoryContextStore
from vulnagent.core.event_bus import EventBus
from vulnagent.core.orchestrator import Orchestrator
from vulnagent.core.task_manager import (
    InMemoryTaskManager,
)
from vulnagent.evidence.store import (
    InMemoryEvidenceStore,
)
from vulnagent.fuzz.mock import MockFuzzEngine
from vulnagent.fuzz.engine import ControlledFuzzEngine
from vulnagent.llm.base import BaseLLM
from vulnagent.llm.router import LLMRouter
from vulnagent.report.generator import (
    StructuredReportGenerator,
)
from vulnagent.settings import (
    Settings,
    get_settings,
)
from vulnagent.storage.sqlite import SQLiteRepository
from vulnagent.verification.verifier import (
    MockVerifier,
)
from vulnagent.verification.evidence_verifier import EvidenceVerifier


MOCK_PROFILE = "mock"
V03_SOURCE_PROFILE = "v03-source"
SUPPORTED_PROFILES = frozenset({MOCK_PROFILE, V03_SOURCE_PROFILE})
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@dataclass(
    frozen=True,
    slots=True,
)
class ApplicationServices:
    """Fully composed process-local VulnAgent service graph."""

    settings: Settings

    task_manager: TaskRepository
    evidence_store: EvidenceRepository
    context_repository: ContextRepository
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
        binary_logic_analyzer=MockLogicAnalyzer(),
        binary_obfuscation_analyzer=MockObfuscationAnalyzer(),
        fuzz_engine=MockFuzzEngine(),
        verifier=MockVerifier(),
        report_generator=StructuredReportGenerator(),
    )


def build_v03_source_capabilities(settings: Settings | None = None) -> CapabilityBundle:
    """Build real Source/Verification/Report capabilities for V0.3.

    Binary inspection is bounded and non-executing. Fuzzing uses the existing
    authorization-gated local controlled executor and remains opt-in.
    """

    resolved_settings = settings if settings is not None else get_settings()

    def resolve(value: str) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else REPOSITORY_ROOT / candidate

    return CapabilityBundle(
        source_parser=SourceProjectParser(),
        source_auditor=MultiLanguageSourceAuditor(),
        binary_analyzer=StaticBinaryReverseAnalyzer(),
        binary_logic_analyzer=LogicAnalyzer(),
        binary_obfuscation_analyzer=ObfuscationAnalyzer(),
        fuzz_engine=ControlledFuzzEngine(),
        verifier=EvidenceVerifier(),
        report_generator=StructuredReportGenerator(),
        program_restorer=ProgramRestorationEngine(
            REPOSITORY_ROOT / "artifacts" / "restoration",
            static_unpacker=UpxAdapter(
                executable=str(resolve(resolved_settings.binary_upx_path)),
                timeout_seconds=resolved_settings.binary_reverse_timeout_seconds,
            ),
            timeout_seconds=resolved_settings.binary_reverse_timeout_seconds,
        ),
        code_deobfuscator=StaticDeobfuscationEngine(),
        code_audit_enabled=True,
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
                name=CapabilityName.BINARY_LOGIC.value,
                description="Locate high-value logic from extracted binary facts",
                adapter=capabilities.binary_logic_analyzer.inspect,
                owner="P5",
                capability_type="binary_semantics",
            ),
            ToolSpec(
                name=CapabilityName.BINARY_OBFUSCATION.value,
                description="Score packing and obfuscation signals from binary facts",
                adapter=capabilities.binary_obfuscation_analyzer.inspect,
                owner="P5",
                capability_type="binary_semantics",
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

    if capabilities.program_restorer is not None:
        registry.register(
            ToolSpec(
                name="binary.restore",
                description="Classify and restore an authorized protected program",
                adapter=capabilities.program_restorer.restore,
                owner="P4",
                capability_type="binary_restoration",
            )
        )
    if capabilities.code_deobfuscator is not None:
        registry.register(
            ToolSpec(
                name="binary.deobfuscate",
                description="Recover OLLVM-style control flow, instructions and strings",
                adapter=capabilities.code_deobfuscator.restore,
                owner="P5",
                capability_type="binary_semantics",
            )
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
    llm: BaseLLM | None = None,
    binary_reverse_workflow: BinaryReverseWorkflow | None = None,
) -> AgentRegistry:
    """Build runtime agents from injected capability Protocols.

    Registry keys deliberately use AgentRoute values rather than
    BaseAgent.name.
    """

    registry = AgentRegistry()

    registry.register_many(
        {
            AgentRoute.PLANNER.value:
                PlannerAgent(
                    llm,
                    code_audit_enabled=capabilities.code_audit_enabled,
                ),

            AgentRoute.SOURCE_ANALYSIS.value:
                SourceAuditAgent(
                    capabilities.source_parser,
                    capabilities.source_auditor,
                ),

            AgentRoute.BINARY_ANALYSIS.value:
                BinaryAnalysisAgent(
                    capabilities.binary_analyzer,
                    capabilities.binary_logic_analyzer,
                    capabilities.binary_obfuscation_analyzer,
                    binary_reverse_workflow,
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

    if capabilities.program_restorer is not None:
        registry.register(
            ProgramRestorationAgent(capabilities.program_restorer),
            key=AgentRoute.PROGRAM_RESTORATION.value,
        )
    if capabilities.code_audit_enabled:
        registry.register(
            CodeAuditAgent(llm),
            key=AgentRoute.CODE_AUDIT.value,
        )
    if capabilities.code_deobfuscator is not None:
        registry.register(
            CodeDeobfuscationAgent(
                capabilities.code_deobfuscator,
                SemanticRecoveryEnhancer(llm),
            ),
            key=AgentRoute.CODE_DEOBFUSCATION.value,
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
    context_repository: ContextRepository | None = None,
    binary_reverse_workflow: BinaryReverseWorkflow | None = None,
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

    storage_backend = resolved_settings.storage_backend.strip().casefold()
    if storage_backend not in {"memory", "sqlite"}:
        raise ValueError(
            f"Unsupported STORAGE_BACKEND {storage_backend!r}; "
            "expected 'memory' or 'sqlite'"
        )
    shared_sqlite = (
        SQLiteRepository(resolved_settings.sqlite_path)
        if storage_backend == "sqlite"
        and task_manager is None
        and evidence_store is None
        and context_repository is None
        else None
    )

    resolved_task_manager = task_manager or shared_sqlite or InMemoryTaskManager()

    resolved_evidence_store = (
        evidence_store or shared_sqlite or InMemoryEvidenceStore()
    )

    resolved_context_repository = (
        context_repository or shared_sqlite or InMemoryContextStore()
    )

    resolved_event_bus = (
        event_bus
        if event_bus is not None
        else EventBus()
    )

    resolved_llm = (
        llm
        if llm is not None
        else LLMRouter.from_settings(resolved_settings).get(
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
            capabilities,
            resolved_llm,
            binary_reverse_workflow,
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
        resolved_context_repository,
    )

    return ApplicationServices(
        settings=resolved_settings,
        task_manager=resolved_task_manager,
        evidence_store=resolved_evidence_store,
        context_repository=resolved_context_repository,
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


def build_v03_source_application(
    *,
    settings: Settings | None = None,
) -> ApplicationServices:
    """Build the canonical V0.3 source-analysis application."""

    resolved_settings = settings if settings is not None else get_settings()
    reverse_workflow = (
        build_binary_reverse_workflow(resolved_settings)
        if resolved_settings.binary_reverse_enabled
        else None
    )
    return build_application(
        build_v03_source_capabilities(resolved_settings),
        settings=resolved_settings,
        binary_reverse_workflow=reverse_workflow,
    )


def build_binary_reverse_workflow(settings: Settings) -> BinaryReverseWorkflow:
    """Compose the offline reverse tools from repository-relative settings."""

    def resolve(value: str) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else REPOSITORY_ROOT / candidate

    timeout = settings.binary_reverse_timeout_seconds
    return BinaryReverseWorkflow(
        resolve(settings.binary_reverse_output_dir),
        inspector=Radare2Adapter(
            executable=str(resolve(settings.binary_radare2_path)),
            timeout_seconds=timeout,
            max_functions=settings.binary_reverse_max_functions,
            max_pseudocode_chars=settings.binary_reverse_max_pseudocode_chars,
        ),
        unpacker=UpxAdapter(
            executable=str(resolve(settings.binary_upx_path)),
            timeout_seconds=timeout,
        ),
    )


def build_profile_application(
    settings: Settings | None = None,
) -> ApplicationServices:
    """Build an application from the explicitly configured profile."""

    resolved_settings = settings if settings is not None else get_settings()
    profile = resolved_settings.vulnagent_profile.strip().casefold()
    if profile == MOCK_PROFILE:
        return build_mock_application(settings=resolved_settings)
    if profile == V03_SOURCE_PROFILE:
        return build_v03_source_application(settings=resolved_settings)
    raise ValueError(
        f"Unsupported VULNAGENT_PROFILE {profile!r}; "
        f"expected one of {sorted(SUPPORTED_PROFILES)}"
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
