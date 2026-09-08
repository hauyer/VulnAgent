"""Unit tests for P7 ReviewerAgent (independent structural second check)."""

from vulnagent.agents import ReviewerAgent
from vulnagent.contracts import (
    AnalysisContext,
    Evidence,
    EvidenceType,
    Target,
    TargetType,
    Task,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)


def make_evidence(evidence_id: str) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        task_id="task-1",
        evidence_type=EvidenceType.SOURCE_LOCATION,
        source="source_audit",
        description="candidate location",
        reliability=0.6,
        created_by="source_audit",
    )


def make_candidate(vulnerability_id: str = "v1", *, evidence_ids: list[str] | None = None) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id=vulnerability_id,
        task_id="task-1",
        title="Potential command injection",
        vulnerability_type="command_injection",
        description="User input may reach an unsafe sink.",
        target_id="target-1",
        location=VulnerabilityLocation(file_path="a.c", function_name="parse", line_start=1, line_end=2),
        source_agent="source_audit",
        source_type="source",
        confidence=0.6,
        severity="HIGH",
        evidence_ids=evidence_ids or [],
    )


def make_verification(vulnerability_id: str = "v1", *, status: VulnerabilityStatus = VulnerabilityStatus.CONFIRMED) -> VerificationResult:
    return VerificationResult(
        vulnerability_id=vulnerability_id,
        task_id="task-1",
        status=status,
        confidence=0.6,
        rationale="independent verification",
        evidence_ids=["e1"],
    )


def make_task() -> Task:
    return Task(task_id="task-1", target=Target(target_id="target-1", path="proj", target_type=TargetType.SOURCE))


async def run_review(findings, *, evidence=None, verifications=None) -> dict:
    task = make_task()
    context = AnalysisContext(
        task=task,
        findings=findings,
        evidence=evidence or [],
        verifications=verifications or [],
    )
    result = await ReviewerAgent().run(task, context)
    return result.messages[0].payload  # REVIEW_RESULT payload


async def test_reviewer_passes_when_evidence_and_verification_are_consistent() -> None:
    evidence = make_evidence("e1")
    finding = make_candidate(evidence_ids=["e1"])
    finding.status = VulnerabilityStatus.CONFIRMED
    payload = await run_review([finding], evidence=[evidence], verifications=[make_verification()])
    assert payload["review_passed"] is True
    assert payload["review_notes"] == []


async def test_reviewer_flags_duplicate_finding() -> None:
    evidence = make_evidence("e1")
    a = make_candidate("v1", evidence_ids=["e1"])
    b = make_candidate("v1", evidence_ids=["e1"])  # same vulnerability_id emitted twice
    payload = await run_review([a, b], evidence=[evidence])
    assert any("duplicate finding" in note for note in payload["review_notes"])


async def test_reviewer_flags_missing_evidence() -> None:
    finding = make_candidate(evidence_ids=[])  # no evidence attached
    payload = await run_review([finding])
    assert any("missing evidence" in note for note in payload["review_notes"])


async def test_reviewer_flags_missing_verification() -> None:
    evidence = make_evidence("e1")
    finding = make_candidate(evidence_ids=["e1"])
    payload = await run_review([finding], evidence=[evidence], verifications=[])
    assert any("missing verification" in note for note in payload["review_notes"])


async def test_reviewer_flags_status_mismatch() -> None:
    evidence = make_evidence("e1")
    finding = make_candidate(evidence_ids=["e1"])
    finding.status = VulnerabilityStatus.CONFIRMED
    payload = await run_review(
        [finding],
        evidence=[evidence],
        verifications=[make_verification(status=VulnerabilityStatus.REJECTED)],
    )
    assert any("status mismatch" in note for note in payload["review_notes"])


async def test_reviewer_flags_missing_required_field() -> None:
    evidence = make_evidence("e1")
    finding = make_candidate(evidence_ids=["e1"])
    finding.title = ""
    payload = await run_review([finding], evidence=[evidence], verifications=[make_verification()])
    assert any("missing required field" in note for note in payload["review_notes"])


async def test_reviewer_passes_on_empty_findings() -> None:
    payload = await run_review([])
    assert payload["review_passed"] is True
    assert payload["reviewed"] == 0
