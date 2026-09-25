"""PUBLIC CONTRACT (new, V0.5): external tool adapter boundary.

Every external engine (Semgrep, Joern, Ghidra, AFL++, angr, ...) is wrapped by
a ``ToolAdapter`` and must speak this boundary.  Core / Agents never import an
engine SDK directly; they only see ``Capability -> ToolRegistry -> Adapter``.
"""
from datetime import datetime
from typing import Any, Protocol

from pydantic import Field

from .common import ContractModel, utc_now


class ToolHealth(ContractModel):
    """Health/availability report shown to the frontend tool dashboard."""

    name: str
    available: bool
    version: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    executable_path: str | None = None
    configured: bool = False
    notes: list[str] = Field(default_factory=list)


class ArtifactRef(ContractModel):
    """Reference to a stored artifact (tool json, crash, corpus, report...)."""

    artifact_id: str
    sha256: str | None = None
    media_type: str | None = None
    size_bytes: int | None = None
    path: str | None = None
    producer: str | None = None


class ProgramFact(ContractModel):
    """A neutral structural fact produced by any analysis tool.

    Typical ``fact_type``: function, call, assignment, condition, source, sink,
    sanitizer, cfg_edge, data_dependency, import, binary_callsite,
    memory_access, string_reference.
    """

    fact_id: str
    fact_type: str
    language: str | None = None
    file_path: str | None = None
    function_name: str | None = None
    line: int | None = None
    binary_address: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    producer: str
    analysis_run_id: str


class NormalizedToolFinding(ContractModel):
    """A tool finding normalized to the platform's neutral shape."""

    finding_id: str
    rule_id: str | None = None
    rule_name: str | None = None
    severity: str | None = None
    cwe_id: str | None = None
    file_path: str | None = None
    function_name: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    message: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class ToolExecutionRequest(ContractModel):
    """A single bounded tool run requested through the adapter boundary."""

    run_id: str
    task_id: str
    session_id: str | None = None
    capability: str
    target_path: str
    authorized: bool = False
    timeout_seconds: int = 60
    options: dict[str, Any] = Field(default_factory=dict)


class ToolExecutionResult(ContractModel):
    """The normalized result of a tool run.

    A failed/missing/timeout tool must return ``success=False`` with a summary
    instead of raising through the pipeline; the Planner decides fallback.
    """

    run_id: str
    capability: str
    provider: str
    executed: bool = False
    success: bool = False
    findings: list[NormalizedToolFinding] = Field(default_factory=list)
    facts: list[ProgramFact] = Field(default_factory=list)
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    stdout_summary: str | None = None
    stderr_summary: str | None = None
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolAdapter(Protocol):
    """Uniform adapter contract every external engine implements."""

    @property
    def name(self) -> str: ...

    @property
    def capabilities(self) -> set[str]: ...

    async def health(self) -> ToolHealth: ...

    async def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult: ...


__all__ = [
    "ArtifactRef",
    "NormalizedToolFinding",
    "ProgramFact",
    "ToolAdapter",
    "ToolExecutionRequest",
    "ToolExecutionResult",
    "ToolHealth",
]
