"""PUBLIC CONTRACT: report generation boundary."""
from typing import Any, Protocol
from pydantic import Field
from .common import ContractModel
from .evidence import Evidence
from .task import Task
from .verification import VerificationResult
from .vulnerability import VulnerabilityCandidate

class ReportRequest(ContractModel):
    task: Task
    findings: list[VulnerabilityCandidate] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)

class ReportResult(ContractModel):
    task_id: str
    content: dict[str, Any] = Field(default_factory=dict)
    artifact_uri: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

class ReportGenerator(Protocol):
    async def generate(self, request: ReportRequest) -> ReportResult: ...
