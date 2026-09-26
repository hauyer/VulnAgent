"""WP5: benchmark adaptation schemas (self-authored, not frozen contracts).

The blind-evaluation protocol keeps every answer artifact on the evaluator
side: ``GroundTruth`` files live in a directory the running Agent never sees,
and ``BlindCaseManifest`` carries only build/harness facts. The evaluator is a
separate process that recomputes ``metrics.json`` from raw candidate and ground
truth rows -- metrics are never hand-maintained.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DatasetName(str, Enum):
    """Where a blind case comes from."""

    SELF = "self"  # VulnAgent self-authored teaching fixture
    EXPLOITGYM_ADAPTED = "exploitgym_adapted"  # adapted under custom protocol
    VULGYM = "vulgym"  # Tencent VulnGym verified item (labels hidden)
    JULIET = "juliet"  # Juliet C/C++ test suite item


class Role(str, Enum):
    DEV = "dev"
    HELD_OUT = "held_out"


class TargetKind(str, Enum):
    SOURCE = "source"
    BINARY = "binary"


class BlindEligibility(str, Enum):
    ELIGIBLE = "eligible"  # answers can be hidden, safe to run locally
    NOT_BLIND = "not_blind"  # answer visible to the agent; case-study only
    UNSAFE = "unsafe"  # cannot be sandboxed safely


class AuthorizationFlags(BaseModel):
    statement: str
    static_read: bool
    file_transform: bool
    dynamic_run: bool
    data_export: bool


class BlindCaseManifest(BaseModel):
    """What the discovery pipeline may see about a benchmark case.

    ``ground_truth_ref`` is a relative path into the evaluator-only directory;
    the running Agent environment must not mount that directory.
    """

    schema_version: int = Field(default=1)
    case_id: str
    opaque_case_id: str = Field(
        default="",
        description=(
            "de-identified handle used inside the agent workspace; the "
            "evaluator remaps candidate rows keyed by this handle to the "
            "dataset case_id"
        ),
    )
    project: str
    family_id: str
    dataset: DatasetName
    role: Role
    target_kind: TargetKind
    language: str
    revision: str  # pinned commit / revision of the project
    target_path: str  # relative to the benchmarks root
    target_sha256: str
    build_spec: dict[str, Any] = Field(default_factory=dict)
    license_record: str
    authorization: AuthorizationFlags
    time_budget_seconds: int = 300
    memory_budget_mb: int = 2048
    blind_eligibility: BlindEligibility = BlindEligibility.ELIGIBLE
    eligibility_reason: str = ""
    ground_truth_ref: str = ""  # evaluator-only relative path


class GroundTruth(BaseModel):
    """The label record. Read only by the independent evaluator process."""

    schema_version: int = Field(default=1)
    case_id: str
    vulnerability_type: str
    cwe_id: str
    title: str
    description: str
    location: str  # file:line or symbol address, evaluator's key for TP match
    trigger_input: str = ""  # hex/bytes or path; hidden from the agent
    fixed_commit: str = ""  # hidden from the agent
    patch_hint: str = ""  # hidden from the agent
    verified: bool = Field(
        default=False,
        description="human/independent verification of the label",
    )


class LabelLeakReport(BaseModel):
    clean: bool
    hard_leaks: list[str] = Field(default_factory=list)
    knowledge_overlap: list[str] = Field(
        default_factory=list,
        description="generic CWE knowledge overlap; recorded, not a failure",
    )


class CaseRunStatus(str, Enum):
    SUCCESS = "success"
    UNSUPPORTED = "unsupported"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    INVALID = "invalid"


class MatchBasis(str, Enum):
    """How a candidate matched a ground truth record (honest localization)."""

    EXACT_LOCATION = "exact_location"  # file:line equal
    SAME_FILE = "same_file"  # file equal, line differs or GT line unknown
    TYPE_ONLY = "type_only"  # CWE / vulnerability type overlap only
    NONE = "none"


class CaseOutcome(BaseModel):
    """One case classified against the hidden ground truth."""

    case_id: str
    dataset: DatasetName
    role: Role
    status: CaseRunStatus
    tp: bool = False
    fp: bool = False
    fn: bool = False
    tn: bool = False  # no GT and no candidate (clean case, not a finding)
    n_candidates: int = 0  # unique root-cause candidates after clustering
    raw_crashes: int = 0  # raw crash observations before clustering
    loc_error: float | None = None  # normalized 0..1 localization error
    match_basis: MatchBasis = MatchBasis.NONE
    gt_count: int = 0
    note: str = ""


class EvaluationResult(BaseModel):
    """Recomputed metrics over the full original denominator.

    Failed/skipped cases are kept in ``per_case`` with their status; precision
    and recall are computed only over evaluable cases while the original
    denominator is reported separately (never silently deleted).  Case-level
    and candidate-level metrics are reported separately; clean cases with no
    candidates never inflate precision/recall to 1.0 (they are ``tn`` rows in
    ``per_case`` and count toward ``total_targets`` only).
    """

    run_id: str
    total_targets: int  # full sample list (manifest/denominator), never 0-dropped
    total_cases: int  # cases that appear in GT or candidate rows
    evaluable_cases: int
    excluded: list[str] = Field(default_factory=list)  # with reasons
    # Candidate-level metrics (each unique root-cause candidate is one unit).
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float | None = None
    recall: float | None = None
    # Case-level metrics.
    case_tp: int = 0
    case_fp: int = 0
    case_fn: int = 0
    case_tn: int = 0
    case_precision: float | None = None
    case_recall: float | None = None
    avg_loc_error: float | None = None
    match_policy: str = "strict"
    per_case: list[CaseOutcome] = Field(default_factory=list)

    def write_metrics(self, path: str) -> None:
        """Persist the recomputed metrics (script-generated, not hand-maintained)."""
        from pathlib import Path

        Path(path).write_text(
            self.model_dump_json(indent=2),
            encoding="utf-8",
        )
