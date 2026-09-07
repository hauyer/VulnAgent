"""Canonical public schemas shared by every VulnAgent module."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(timezone.utc)


class TargetType(str, Enum):
    SOURCE = "source"
    BINARY = "binary"
    PROJECT = "project"
    ARCHIVE = "archive"


class TaskStatus(str, Enum):
    CREATED = "created"
    PROFILING = "profiling"
    PLANNING = "planning"
    ANALYZING = "analyzing"
    DYNAMIC_TESTING = "dynamic_testing"
    VERIFYING = "verifying"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnerabilityStatus(str, Enum):
    CANDIDATE = "candidate"
    VERIFYING = "verifying"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNCERTAIN = "uncertain"


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


class AgentMessageType(str, Enum):
    TASK = "task"
    PLAN = "plan"
    REQUEST_ANALYSIS = "request_analysis"
    ANALYSIS_RESULT = "analysis_result"
    VULNERABILITY_CANDIDATE = "vulnerability_candidate"
    REQUEST_VERIFICATION = "request_verification"
    VERIFICATION_RESULT = "verification_result"
    FUZZ_REQUEST = "fuzz_request"
    FUZZ_RESULT = "fuzz_result"
    EVIDENCE_UPDATE = "evidence_update"
    REVIEW_REQUEST = "review_request"
    REVIEW_RESULT = "review_result"
    REPORT_REQUEST = "report_request"
    REPORT_RESULT = "report_result"
    ERROR = "error"


class Target(BaseModel):
    target_id: str
    path: str
    target_type: TargetType
    language: str | None = None
    file_format: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Task(BaseModel):
    task_id: str
    target: Target
    status: TaskStatus = TaskStatus.CREATED
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityLocation(BaseModel):
    file_path: str | None = None
    function_name: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    binary_address: str | None = None
    module_name: str | None = None


class VulnerabilityCandidate(BaseModel):
    vulnerability_id: str
    task_id: str
    title: str
    vulnerability_type: str
    cwe_id: str | None = None
    description: str
    target_id: str
    location: VulnerabilityLocation | None = None
    source_agent: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    status: VulnerabilityStatus = VulnerabilityStatus.CANDIDATE
    metadata: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
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


class AgentMessage(BaseModel):
    message_id: str
    task_id: str
    sender: str
    receiver: str | None = None
    message_type: AgentMessageType
    payload: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class AgentResult(BaseModel):
    agent_name: str
    success: bool = True
    messages: list[AgentMessage] = Field(default_factory=list)
    findings: list[VulnerabilityCandidate] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    error: str | None = None


class AnalysisContext(BaseModel):
    task: Task
    messages: list[AgentMessage] = Field(default_factory=list)
    findings: list[VulnerabilityCandidate] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

