"""Prove the real EvidenceVerifier composes via P1's public DI boundary.

``bootstrap.build_application`` is the documented primary dependency-injection
boundary and accepts a ``CapabilityBundle``.  This test builds a bundle with the
real ``EvidenceVerifier`` (everything else still Mock) and runs one full
orchestration task through the composition root -- without editing bootstrap.py.

It proves P7's V0.3 verifier can take over the whole pipeline as soon as the
composition caller chooses it; P1 does not need a code change for P7 to run.
"""

from vulnagent.analyzers.binary.reverse import MockBinaryReverseAnalyzer
from vulnagent.analyzers.binary.logic import MockLogicAnalyzer
from vulnagent.analyzers.binary.obfuscation import MockObfuscationAnalyzer
from vulnagent.analyzers.source.audit import MockSourceAuditor
from vulnagent.analyzers.source.parser import MockSourceParser
from vulnagent.bootstrap import build_application
from vulnagent.contracts import Target, TargetType, TaskStatus, VulnerabilityStatus
from vulnagent.core.dependencies import CapabilityBundle
from vulnagent.fuzz.mock import MockFuzzEngine
from vulnagent.report.generator import MockReportGenerator
from vulnagent.verification.evidence_verifier import EvidenceVerifier


async def test_evidence_verifier_runs_through_public_composition_root() -> None:
    services = build_application(
        CapabilityBundle(
            source_parser=MockSourceParser(),
            source_auditor=MockSourceAuditor(),
            binary_analyzer=MockBinaryReverseAnalyzer(),
            binary_logic_analyzer=MockLogicAnalyzer(),
            binary_obfuscation_analyzer=MockObfuscationAnalyzer(),
            fuzz_engine=MockFuzzEngine(),
            verifier=EvidenceVerifier(),
            report_generator=MockReportGenerator(),
        )
    )

    task = services.task_manager.create_task(
        Target(
            target_id="composition-demo",
            path="safe-mock-fixture",
            target_type=TargetType.SOURCE,
        )
    )
    context = await services.orchestrator.run(task.task_id)

    assert context.task.status is TaskStatus.COMPLETED
    assert context.findings
    assert context.verifications
    # The real, evidence-driven verifier is the one producing verdicts.
    assert all(item.metadata.get("verifier") == "EvidenceVerifier" for item in context.verifications)
    # Every finding reached a final verdict through the verification boundary.
    assert all(
        finding.status
        in {
            VulnerabilityStatus.CONFIRMED,
            VulnerabilityStatus.REJECTED,
            VulnerabilityStatus.UNCERTAIN,
        }
        for finding in context.findings
    )
    # Verdict rationale is recorded per finding for reporting.
    assert any(
        item.metadata.get("verifier") == "EvidenceVerifier"
        and item.rationale
        for item in context.verifications
    )
