import pytest

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    ReportRequest,
    Target,
    TargetType,
    Task,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityStatus,
)
from vulnagent.report.generator import MockReportGenerator


@pytest.mark.asyncio
async def test_report_exposes_evidence_chain_and_explicit_limitations() -> None:
    task = Task(task_id="task-1", target=Target(target_id="target-1", path="fixture.py", target_type=TargetType.SOURCE))
    finding = VulnerabilityCandidate(
        vulnerability_id="finding-1",
        task_id=task.task_id,
        title="Unsafe input",
        vulnerability_type="injection",
        description="Fixture finding",
        target_id="target-1",
        source_agent="audit",
        confidence=0.7,
        evidence_ids=["evidence-1", "missing-evidence"],
    )
    evidence = Evidence(
        evidence_id="evidence-1",
        task_id=task.task_id,
        evidence_type=EvidenceType.SOURCE_LOCATION,
        source="audit",
        description="Located in fixture.py",
        reliability=0.8,
        created_by="audit",
    )
    verification = VerificationResult(
        vulnerability_id="finding-1",
        task_id=task.task_id,
        status=VulnerabilityStatus.CONFIRMED,
        confidence=0.9,
        rationale="Reproduced safely",
        evidence_ids=["evidence-1"],
    )

    report = await MockReportGenerator().generate(ReportRequest(
        task=task, findings=[finding], evidence=[evidence], verifications=[verification]
    ))

    assert report.content["summary"]["finding_count"] == 1
    assert report.content["findings"][0]["verification"]["status"] == "confirmed"
    assert report.content["limitations"]["missing_evidence_ids"] == ["missing-evidence"]
    assert report.content["evidence_graph"]["edges"]
