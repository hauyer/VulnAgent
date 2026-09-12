"""Credential-free ViewModels for the local test laboratory."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


def utc_iso() -> str:
    """Return an ISO-8601 UTC timestamp for UI projections."""

    return datetime.now(timezone.utc).isoformat()


class LabCategory(str, Enum):
    """The three explicitly supported course-test categories."""

    LOCAL_LLM = "local_llm"
    PACKED_BINARY = "packed_binary"
    OBFUSCATED_BINARY = "obfuscated_binary"


class LabRunState(str, Enum):
    """Lifecycle of one user-triggered laboratory run."""

    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"


class LocalModelTarget(BaseModel):
    """One locally deployed OpenAI-compatible model endpoint."""

    name: str = Field(min_length=1, max_length=80)
    base_url: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1, max_length=200)


class BinaryLabTarget(BaseModel):
    """One local, explicitly authorized protected software target."""

    name: str = Field(min_length=1, max_length=120)
    path: str = Field(min_length=1, max_length=1000)
    version: str | None = Field(default=None, max_length=120)
    protector: str | None = Field(default=None, max_length=160)
    protection_strength: Literal[
        "unknown", "none", "compression", "encryption", "light_virtualization", "code_obfuscation"
    ] = "unknown"
    expected_sha256: str | None = Field(default=None, pattern=r"^[A-Fa-f0-9]{64}$")
    authorization_confirmed: bool = False
    dynamic_validation: bool = False
    validation_inputs: list[str] = Field(default_factory=list, max_length=8)
    emulator_serial: str | None = Field(default=None, pattern=r"^emulator-[0-9]+$")

    @model_validator(mode="after")
    def validate_dynamic_authorization(self) -> "BinaryLabTarget":
        """Dynamic validation always requires an explicit authorization ack."""

        if self.dynamic_validation and not self.authorization_confirmed:
            raise ValueError("dynamic_validation requires authorization_confirmed=true")
        if any(len(item.encode("utf-8")) > 4096 for item in self.validation_inputs):
            raise ValueError("each validation input must be at most 4096 UTF-8 bytes")
        return self


class LabRunRequest(BaseModel):
    """Configuration submitted by the four-panel frontend workflow."""

    category: LabCategory
    name: str = Field(default="课程授权测试", min_length=1, max_length=120)
    local_models: list[LocalModelTarget] = Field(default_factory=list, max_length=6)
    binary_targets: list[BinaryLabTarget] = Field(default_factory=list, max_length=6)
    audit_text: str = Field(
        default="result = eval(input())",
        min_length=1,
        max_length=16_000,
    )
    expected_cwe_id: str = Field(default="CWE-95", min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_category_targets(self) -> "LabRunRequest":
        """Require one runnable target while retaining distinct batch entries."""

        if self.category is LabCategory.LOCAL_LLM:
            if not self.local_models:
                raise ValueError("local_llm runs require at least one local model")
            identities = {
                (item.base_url.rstrip("/").casefold(), item.model.casefold())
                for item in self.local_models
            }
            if len(identities) != len(self.local_models):
                raise ValueError("local_llm batch targets must be distinct")
            if self.binary_targets:
                raise ValueError("local_llm runs cannot include binary_targets")
        else:
            if not self.binary_targets:
                raise ValueError("protected binary runs require at least one target")
            paths = {item.path.strip().casefold() for item in self.binary_targets}
            if len(paths) != len(self.binary_targets):
                raise ValueError("protected binary batch targets must use distinct paths")
            if self.local_models:
                raise ValueError("protected binary runs cannot include local_models")
        return self


class LabLogEntry(BaseModel):
    """One sanitized, user-visible progress record."""

    timestamp: str = Field(default_factory=utc_iso)
    stage: Literal["intake", "discovery", "verification", "report"]
    level: Literal["info", "success", "warning", "error"] = "info"
    target: str | None = None
    message: str


class LabTargetResult(BaseModel):
    """One model or protected-binary result row."""

    target_name: str
    status: Literal["completed", "partial", "failed", "blocked"]
    task_id: str | None = None
    sha256: str | None = None
    finding_count: int = 0
    confirmed_count: int = 0
    uncertain_count: int = 0
    evidence_count: int = 0
    discovery: dict[str, Any] = Field(default_factory=dict)
    verification: dict[str, Any] = Field(default_factory=dict)
    sandbox: dict[str, Any] = Field(default_factory=dict)
    report_available: bool = False
    error: str | None = None


class LabRun(BaseModel):
    """Complete local test run returned to and rendered by the frontend."""

    run_id: str
    name: str
    category: LabCategory
    state: LabRunState = LabRunState.QUEUED
    created_at: str = Field(default_factory=utc_iso)
    updated_at: str = Field(default_factory=utc_iso)
    target_count: int
    dynamic_validation_requested: bool = False
    logs: list[LabLogEntry] = Field(default_factory=list)
    results: list[LabTargetResult] = Field(default_factory=list)
    archived_task_ids: list[str] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class LabArchiveResult(BaseModel):
    """Receipt returned after recording completed tasks in the dossier."""

    run_id: str
    task_ids: list[str] = Field(default_factory=list)
    finding_count: int = 0
    evidence_count: int = 0
    report_count: int = 0


class LabCapability(BaseModel):
    """One frontend-friendly capability and its truthful safety boundary."""

    category: LabCategory
    title: str
    supported_targets: str
    minimum_targets: int = 1
    stages: list[str]
    safety_boundary: str
