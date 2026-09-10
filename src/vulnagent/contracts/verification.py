"""PUBLIC CONTRACT: independent verification boundary."""
from typing import Any, Protocol
from pydantic import Field
from .common import ContractModel
from .evidence import Evidence
from .vulnerability import VulnerabilityCandidate, VulnerabilityStatus

class VerificationContext(ContractModel):
    task_id: str
    evidence: list[Evidence] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

class VerificationResult(ContractModel):
    vulnerability_id: str
    task_id: str
    status: VulnerabilityStatus
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

class VulnerabilityVerifier(Protocol):
    async def verify(self, candidate: VulnerabilityCandidate, context: VerificationContext) -> VerificationResult: ...
