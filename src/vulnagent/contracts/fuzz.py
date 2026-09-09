"""PUBLIC CONTRACT: safe fuzzing boundary."""
from typing import Any, Protocol
from pydantic import Field
from .common import ContractModel
from .evidence import Evidence

class FuzzRequest(ContractModel):
    task_id: str
    target_id: str
    target_path: str
    authorized: bool = False
    time_budget_seconds: int = Field(default=1, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)

class FuzzResult(ContractModel):
    task_id: str
    target_id: str
    executed: bool = False
    crashes: int = Field(default=0, ge=0)
    coverage: float | None = Field(default=None, ge=0.0)
    evidence: list[Evidence] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

class FuzzEngine(Protocol):
    async def run(self, request: FuzzRequest) -> FuzzResult: ...
