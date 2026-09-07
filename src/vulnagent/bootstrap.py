"""Application composition root.

Concrete implementations are wired only here so business modules depend on ports.
"""

from vulnagent.agents import BinaryAnalysisAgent, FuzzAgent, PlannerAgent, ReportAgent, ReviewerAgent, SourceAuditAgent, VerificationAgent
from vulnagent.agent_runtime import AgentRuntime, AgentSuite, RuntimePolicy, ToolRegistry, ToolSpec
from vulnagent.analyzers.binary.reverse import MockBinaryReverseAnalyzer
from vulnagent.analyzers.source.audit import MockSourceAuditor
from vulnagent.analyzers.source.parser import MockSourceParser
from vulnagent.core.event_bus import EventBus
from vulnagent.core.orchestrator import Orchestrator
from vulnagent.core.task_manager import InMemoryTaskManager
from vulnagent.evidence.store import InMemoryEvidenceStore
from vulnagent.fuzz.mock import MockFuzzEngine
from vulnagent.llm.router import LLMRouter
from vulnagent.report.generator import MockReportGenerator
from vulnagent.settings import get_settings
from vulnagent.verification.verifier import MockVerifier


def build_mock_services() -> tuple[InMemoryTaskManager, InMemoryEvidenceStore, Orchestrator]:
    """Build an isolated, safe, non-executing V0.2 service graph."""
    task_manager = InMemoryTaskManager()
    evidence_store = InMemoryEvidenceStore()
    settings = get_settings()
    source_parser = MockSourceParser()
    source_auditor = MockSourceAuditor()
    binary_analyzer = MockBinaryReverseAnalyzer()
    fuzz_engine = MockFuzzEngine()
    verifier = MockVerifier()
    report_generator = MockReportGenerator()
    agents = AgentSuite(
        planner=PlannerAgent(),
        source_analysis=SourceAuditAgent(source_parser, source_auditor),
        binary_analysis=BinaryAnalysisAgent(binary_analyzer),
        fuzz=FuzzAgent(fuzz_engine),
        verification=VerificationAgent(verifier),
        reviewer=ReviewerAgent(),
        report=ReportAgent(report_generator),
    )
    tools = ToolRegistry()
    tools.register(ToolSpec("source.parse", "Parse source structure", source_parser.analyze, "P2", "source"))
    tools.register(ToolSpec("source.audit", "Audit parsed source", source_auditor.audit, "P3", "source"))
    tools.register(ToolSpec("binary.inspect", "Inspect binary statically", binary_analyzer.analyze, "P4", "binary"))
    tools.register(ToolSpec("fuzz.execute", "Run an authorization-gated fuzz adapter", fuzz_engine.run, "P6", "dynamic"))
    tools.register(ToolSpec("verification.verify", "Verify one candidate independently", verifier.verify, "P7", "verification"))
    tools.register(ToolSpec("report.generate", "Generate a structured report", report_generator.generate, "P9", "report"))
    llm_router = LLMRouter()
    event_bus = EventBus()
    runtime = AgentRuntime(
        agents.as_mapping(),
        policy=RuntimePolicy(max_agent_steps=settings.max_agent_steps, max_route_repeats=settings.max_route_repeats),
        publish_event=event_bus.publish,
        tool_registry=tools,
        llm=llm_router.get(settings.llm_provider),
    )
    return task_manager, evidence_store, Orchestrator(task_manager, evidence_store, runtime, event_bus)
