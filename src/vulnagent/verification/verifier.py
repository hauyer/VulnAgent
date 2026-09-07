"""Verification capability facade."""

from vulnagent.core.models import VulnerabilityCandidate, VulnerabilityStatus


class MockVerifier:
    """Return a copied mock candidate with an explicitly uncertain result."""

    def verify(self, candidate: VulnerabilityCandidate) -> VulnerabilityCandidate:
        result = candidate.model_copy(deep=True)
        result.status = VulnerabilityStatus.UNCERTAIN
        return result

