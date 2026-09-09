"""Verification capability facade."""
from vulnagent.contracts import VerificationContext, VerificationResult, VulnerabilityCandidate, VulnerabilityStatus


class MockVerifier:
    """Return a structured result without mutating the candidate."""

    async def verify(self, candidate: VulnerabilityCandidate, context: VerificationContext) -> VerificationResult:
        status = VulnerabilityStatus.UNCERTAIN if candidate.metadata.get("mock") else VulnerabilityStatus.REJECTED
        return VerificationResult(vulnerability_id=candidate.vulnerability_id, task_id=candidate.task_id, status=status, confidence=candidate.confidence, rationale="Independent mock verification; no sufficient runtime proof.", evidence_ids=[item.evidence_id for item in context.evidence], metadata={"mock": True})
