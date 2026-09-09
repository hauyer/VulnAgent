"""PUBLIC CONTRACT: structured orchestration events."""
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import Field
from .common import ContractModel, utc_now

class EventType(str, Enum):
    TASK_STARTED = "task_started"
    AGENT_STARTED = "agent_started"
    AGENT_FINISHED = "agent_finished"
    CANDIDATE_CREATED = "candidate_created"
    VERIFICATION_STARTED = "verification_started"
    VULNERABILITY_CONFIRMED = "vulnerability_confirmed"
    VULNERABILITY_REJECTED = "vulnerability_rejected"
    EVIDENCE_ADDED = "evidence_added"
    REPORT_GENERATED = "report_generated"
    TASK_FAILED = "task_failed"
    AGENT_ROUTED = "agent_routed"
    AGENT_RETRY = "agent_retry"
    REVIEW_COMPLETED = "review_completed"

class DomainEvent(ContractModel):
    event_type: EventType
    task_id: str
    producer: str
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)
