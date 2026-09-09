"""PUBLIC CONTRACT: evidence DTO and repository port."""
from datetime import datetime
from enum import Enum
from typing import Any, Protocol
from pydantic import Field
from .common import ContractModel, utc_now

class EvidenceType(str, Enum):
    SOURCE_LOCATION = "source_location"
    CODE_SNIPPET = "code_snippet"
    CALL_PATH = "call_path"
    DATA_FLOW = "data_flow"
    TAINT_PATH = "taint_path"
    BINARY_ADDRESS = "binary_address"
    DISASSEMBLY = "disassembly"
    CFG_PATH = "cfg_path"
    FUZZ_INPUT = "fuzz_input"
    COVERAGE = "coverage"
    CRASH_LOG = "crash_log"
    STACK_TRACE = "stack_trace"
    SANITIZER_OUTPUT = "sanitizer_output"
    RUNTIME_TRACE = "runtime_trace"
    TOOL_RESULT = "tool_result"
    MODEL_REASONING_SUMMARY = "model_reasoning_summary"
    VERIFICATION_RESULT = "verification_result"

class Evidence(ContractModel):
    evidence_id: str
    task_id: str
    evidence_type: EvidenceType
    source: str
    description: str
    artifact_path: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    reliability: float = Field(ge=0.0, le=1.0)
    created_by: str
    created_at: datetime = Field(default_factory=utc_now)

class EvidenceRepository(Protocol):
    def save(self, evidence: Evidence) -> Evidence: ...
    def get(self, evidence_id: str) -> Evidence | None: ...
    def list_by_task(self, task_id: str) -> list[Evidence]: ...
