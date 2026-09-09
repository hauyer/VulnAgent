"""PUBLIC CONTRACT: binary analysis boundaries."""
from typing import Any, Protocol
from pydantic import Field
from .common import ContractModel

class BinaryAnalysisRequest(ContractModel):
    task_id: str
    target_id: str
    path: str

class BinaryAnalysisResult(ContractModel):
    task_id: str
    target_id: str
    path: str
    file_format: str | None = None
    architecture: str | None = None
    strings: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    functions: list[dict[str, Any]] = Field(default_factory=list)
    cfg: dict[str, list[str]] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

class BinaryAnalyzer(Protocol):
    async def analyze(self, request: BinaryAnalysisRequest) -> BinaryAnalysisResult: ...

class BinaryFeatureAnalyzer(Protocol):
    async def inspect(self, result: BinaryAnalysisResult) -> dict[str, Any]: ...
