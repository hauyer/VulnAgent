"""PUBLIC CONTRACT: task lifecycle and target DTOs."""
from datetime import datetime
from enum import Enum
from typing import Any, Protocol
from pydantic import Field
from .common import ContractModel, utc_now

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

class Target(ContractModel):
    target_id: str
    path: str
    target_type: TargetType
    language: str | None = None
    file_format: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

class Task(ContractModel):
    task_id: str
    target: Target
    status: TaskStatus = TaskStatus.CREATED
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaskRepository(Protocol):
    """Task persistence port consumed by orchestration."""

    def get_task(self, task_id: str) -> Task | None: ...
    def update_task(self, task_id: str, *, status: TaskStatus | None = None, error: str | None = None, metadata: dict[str, Any] | None = None) -> Task: ...
