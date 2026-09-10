"""PUBLIC CONTRACT: agent messages, results, and context."""
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import Field
from .common import ContractModel, utc_now
from .evidence import Evidence
from .task import Task
from .verification import VerificationResult
from .vulnerability import VulnerabilityCandidate
from .report import ReportResult

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

class AgentMessage(ContractModel):
    message_id: str
    task_id: str
    sender: str
    receiver: str | None = None
    message_type: AgentMessageType
    payload: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)

class AgentResult(ContractModel):
    agent_name: str
    success: bool = True
    messages: list[AgentMessage] = Field(default_factory=list)
    findings: list[VulnerabilityCandidate] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)
    reports: list[ReportResult] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    error: str | None = None

class AnalysisContext(ContractModel):
    task: Task
    messages: list[AgentMessage] = Field(default_factory=list)
    findings: list[VulnerabilityCandidate] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)
    reports: list[ReportResult] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
