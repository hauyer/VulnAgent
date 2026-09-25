"""Target admission models for the vulnerability-discovery practice (WP0).

These are **internal experiment DTOs**, not the frozen public contracts
(``Task`` / ``AgentMessage`` / ``VulnerabilityCandidate`` / ``Evidence``).
They describe how a target is registered, authorized, version-pinned and
hashed before any analysis runs.

The hidden ground-truth label is referenced by ``ground_truth_ref`` only.  It
is held by the independent evaluation process and must never be injected into
an agent-facing task, prompt or log.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from vulnagent.contracts.common import ContractModel


class DatasetRole(str, Enum):
    """How a sample may be used during development and evaluation."""

    TRAIN = "train"
    VALIDATION = "validation"
    HELD_OUT = "held_out"
    EXPLORATORY = "exploratory"


class TargetKind(str, Enum):
    """The shape of the pinned target."""

    SOURCE = "source"
    BINARY = "binary"
    PROJECT = "project"


class Authorization(ContractModel):
    """Four independent authorization dimensions.

    Consent cannot be represented by one boolean: reading source, transforming
    files, executing code and exporting data are separate grants that default
    to deny.
    """

    statement: str = ""
    record_ref: str | None = None
    static_read: bool = True
    file_transform: bool = False
    dynamic_run: bool = False
    data_export: bool = False


class TargetManifest(ContractModel):
    """An immutable admission record for one target.

    Aligned with the practice-plan sample manifest (section 3.2) and the
    guide interface (section 5.1).  The analyzer only ever sees the pinned
    target; ``ground_truth_ref`` points at a label the evaluation process
    keeps private.
    """

    sample_id: str
    source_name: str
    role: DatasetRole
    revision: str
    target_path: str
    target_sha256: str
    license_record: str

    family_id: str | None = None
    dataset: str = "local"
    target_kind: TargetKind = TargetKind.SOURCE
    language: str | None = None

    upstream_uri: str | None = None
    fixed_revision: str | None = None

    authorization: Authorization = Field(default_factory=Authorization)
    build_profile: str | None = None
    ground_truth_ref: str | None = None

    time_budget_seconds: int = Field(default=300, gt=0, le=3600)
    memory_budget_mb: int = Field(default=2048, gt=0, le=65536)

    @property
    def static_allowed(self) -> bool:
        """Whether static reading is granted."""

        return self.authorization.static_read

    @property
    def dynamic_allowed(self) -> bool:
        """Whether dynamic execution is granted."""

        return self.authorization.dynamic_run


class IntakeReason(str, Enum):
    """Machine-readable reason codes emitted by the intake gate."""

    ACCEPTED = "accepted"
    INVALID_MANIFEST = "invalid_manifest"
    MISSING_REVISION = "missing_revision"
    MISSING_LICENSE = "missing_license"
    INVALID_SHA256 = "invalid_sha256"
    NETWORK_PATH = "network_path"
    INVALID_PATH = "invalid_path"
    PATH_ESCAPE = "path_escape"
    MISSING_TARGET = "missing_target"
    SHA256_MISMATCH = "sha256_mismatch"
    SIZE_LIMIT = "size_limit"
    AUTHORIZATION_MISMATCH = "authorization_mismatch"
    LABEL_LEAK = "label_leak"


class IntakeDecision(ContractModel):
    """The read-only verdict returned by a :class:`TargetIntake`."""

    sample_id: str
    accepted: bool
    reason_codes: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    normalized_path: str | None = None
    checked_sha256: str | None = None
    role: DatasetRole | None = None
    dynamic_allowed: bool = False
