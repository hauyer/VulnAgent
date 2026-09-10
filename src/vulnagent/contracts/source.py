"""PUBLIC CONTRACT: source parsing and audit boundaries."""
from typing import Any, Protocol
from pydantic import Field
from .common import ContractModel
from .vulnerability import VulnerabilityCandidate

class ProjectInput(ContractModel):
    task_id: str
    target_id: str
    project_path: str
    metadata: dict[str, Any] = Field(default_factory=dict)

class SourceAnalysisResult(ContractModel):
    task_id: str
    target_id: str
    project_path: str
    languages: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    symbols: list[dict[str, Any]] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    call_graph: dict[str, list[str]] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

class SourceParser(Protocol):
    async def analyze(self, request: ProjectInput) -> SourceAnalysisResult: ...

class SourceAuditor(Protocol):
    async def audit(self, result: SourceAnalysisResult) -> list[VulnerabilityCandidate]: ...
