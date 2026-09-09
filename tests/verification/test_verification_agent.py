"""Unit tests for P7 VerificationAgent (verification boundary)."""

from vulnagent.agents import VerificationAgent
from vulnagent.contracts import (
    AnalysisContext,
    Evidence,
    EvidenceType,
    Target,
    TargetType,
    Task,
    VerificationContext,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)


def make_candidate(
    vulnerability_id: str,
    *,
    location: VulnerabilityLocation | None = None,
    evidence_ids: list[str] | None = None,
) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id=vulnerability_id,
        task_id="task-1",
        title="Potential command injection",
        vulnerability_type="command_injection",
        description="User input may reach an unsafe sink.",
        target_id="target-1",
        location=location or VulnerabilityLocation(file_path="a.c", function_name="parse", line_start=1, line_end=2),
        source_agent="source_audit",
        source_type="source",
        confidence=0.6,
        severity="HIGH",
        evidence_ids=evidence_ids or [],
    )


def make_evidence(evidence_id: str) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        task_id="task-1",
        evidence_type=EvidenceType.SOURCE_LOCATION,
        source="source_audit",
        description="discovery evidence",
        reliability=0.6,
        created_by="source_audit",
    )


def make_task() -> Task:
    return Task(task_id="task-1", target=Target(target_id="target-1", path="proj", target_type=TargetType.SOURCE))


class RecordingVerifier:
    """Injected verifier that records every candidate it is asked to verify."""

    def __init__(self, status: VulnerabilityStatus = VulnerabilityStatus.UNCERTAIN, *, request_additional: bool = False) -> None:
        self.status = status
        self.request_additional = request_additional
        self.called_ids: list[str] = []

    async def verify(self, candidate: VulnerabilityCandidate, context: VerificationContext) -> VerificationResult:
        self.called_ids.append(candidate.vulnerability_id)
        return VerificationResult(
            vulnerability_id=candidate.vulnerability_id,
            task_id=candidate.task_id,
            status=self.status,
            confidence=candidate.confidence,
            rationale="independent mock verification",
            evidence_ids=[item.evidence_id for item in context.evidence],
            metadata={"request_additional_analysis": self.request_additional},
        )


async def test_verification_agent_canonicalizes_duplicates_before_verifying() -> None:
    task = make_task()
    evidence = [make_evidence("e1"), make_evidence("e2")]
    v1 = make_candidate("v1", evidence_ids=["e1"])
    v2 = make_candidate("v2", evidence_ids=["e2"])  # duplicate of v1 (same target/type/location)
    v3 = make_candidate("v3", location=VulnerabilityLocation(file_path="b.c", function_name="send", line_start=9, line_end=12), evidence_ids=["e1"])
    verifier = RecordingVerifier()
    agent = VerificationAgent(verifier)
    result = await agent.run(task, AnalysisContext(task=task, findings=[v1, v2, v3], evidence=evidence))

    # The merged duplicate is not independently verified; evidence is fused onto the
    # canonical candidate and the merged id stays traceable.
    assert verifier.called_ids == ["v1", "v3"]
    assert [item.vulnerability_id for item in result.findings] == ["v1", "v3"]
    assert [item.vulnerability_id for item in result.verifications] == ["v1", "v3"]

    canonical = next(item for item in result.findings if item.vulnerability_id == "v1")
    assert {"e1", "e2"}.issubset(canonical.evidence_ids)  # evidence fused
    assert canonical.metadata["duplicate_ids"] == ["v2"]  # traceable
    assert result.messages[0].payload.get("merged") == 1


async def test_verification_agent_applies_only_final_status() -> None:
    task = make_task()
    verifier = RecordingVerifier(VulnerabilityStatus.REJECTED)
    agent = VerificationAgent(verifier)
    result = await agent.run(task, AnalysisContext(task=task, findings=[make_candidate("v1")]))

    assert result.findings[0].status is VulnerabilityStatus.REJECTED
    assert result.verifications[0].status is VulnerabilityStatus.REJECTED
    assert all(item.status.value in {"confirmed", "rejected", "uncertain"} for item in result.findings)


async def test_verification_agent_creates_per_finding_verification_evidence() -> None:
    task = make_task()
    agent = VerificationAgent(RecordingVerifier())
    result = await agent.run(task, AnalysisContext(task=task, findings=[make_candidate("v1")]))

    verification_evidence = [item for item in result.evidence if item.evidence_type is EvidenceType.VERIFICATION_RESULT]
    assert len(verification_evidence) == 1
    # The verdict evidence id is attached to the finding it documents.
    assert result.findings[0].evidence_ids[-1] == verification_evidence[0].evidence_id
    # The verdict evidence records the rationale for traceability.
    assert verification_evidence[0].data["status"] == "uncertain"
    assert verification_evidence[0].data["rationale"]


async def test_verification_agent_does_not_mutate_input_candidates() -> None:
    task = make_task()
    original = make_candidate("v1")
    context = AnalysisContext(task=task, findings=[original])
    agent = VerificationAgent(RecordingVerifier(VulnerabilityStatus.CONFIRMED))
    await agent.run(task, context)

    assert original.status is VulnerabilityStatus.CANDIDATE
    assert original.evidence_ids == []


async def test_verification_agent_propagates_additional_analysis_request() -> None:
    task = make_task()
    verifier = RecordingVerifier(VulnerabilityStatus.UNCERTAIN, request_additional=True)
    agent = VerificationAgent(verifier)
    result = await agent.run(task, AnalysisContext(task=task, findings=[make_candidate("v1")]))

    assert result.messages[0].payload.get("request_additional_analysis") is True
