"""Application composition root.

Concrete implementations are wired only here so business modules depend on ports.
"""

from vulnagent.agents import BinaryAnalysisAgent, FuzzAgent, PlannerAgent, ReportAgent, ReviewerAgent, SourceAuditAgent, VerificationAgent
from vulnagent.analyzers.binary.reverse import MockBinaryReverseAnalyzer
from vulnagent.analyzers.source.audit import MockSourceAuditor
from vulnagent.analyzers.source.parser import MockSourceParser
from vulnagent.core.orchestrator import AgentSuite, Orchestrator
from vulnagent.core.task_manager import InMemoryTaskManager
from vulnagent.evidence.store import InMemoryEvidenceStore
from vulnagent.fuzz.mock import MockFuzzEngine
from vulnagent.report.generator import MockReportGenerator
from vulnagent.verification.verifier import MockVerifier


def build_mock_services() -> tuple[InMemoryTaskManager, InMemoryEvidenceStore, Orchestrator]:
    """Build an isolated, safe, non-executing V0.1 service graph."""
    task_manager = InMemoryTaskManager()
    evidence_store = InMemoryEvidenceStore()
    agents = AgentSuite(
        planner=PlannerAgent(),
        source_analysis=SourceAuditAgent(MockSourceParser(), MockSourceAuditor()),
        binary_analysis=BinaryAnalysisAgent(MockBinaryReverseAnalyzer()),
        fuzz=FuzzAgent(MockFuzzEngine()),
        verification=VerificationAgent(MockVerifier()),
        reviewer=ReviewerAgent(),
        report=ReportAgent(MockReportGenerator()),
    )
    return task_manager, evidence_store, Orchestrator(task_manager, evidence_store, agents)
