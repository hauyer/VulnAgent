"""Public acceptance ViewModels (not frozen contracts).

These read-only DTOs project manifest/artifact/provider facts into a
frontend-ready shape. They intentionally reuse no frozen Schema names so the
architecture contract guard ``test_public_contract_names_are_not_redefined``
stays green, and they never carry API keys, Authorization headers, or
sensitive absolute paths.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AcceptanceStatus(str, Enum):
    """The six-value course-test acceptance state machine."""

    NOT_RUN = "not_run"
    RUNNING = "running"
    PASS = "pass"
    PARTIAL = "partial"
    FAIL = "fail"
    BLOCKED = "blocked"


class ProviderStatus(BaseModel):
    """Configured-model status without credentials."""

    provider: str
    configured: bool
    is_mock: bool
    model: str | None = None
    base_url: str | None = None
    default_for_planner: bool = False


class ProviderComparison(BaseModel):
    """One aggregated run metric from the llm-comparison artifacts."""

    method: str
    samples: int = 0
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    total_token_cost: float | None = None
    token_cost_currency: str | None = None
    mean_duration_seconds: float | None = None
    confirmed_finding_count: int = 0
    evidence_chain_coverage: float = 0.0


class LLMComparisonSummary(BaseModel):
    """Display-safe current artifact or published real-comparison baseline."""

    source: str = "unavailable"
    snapshot_id: str | None = None
    generated_at: str | None = None
    benchmark_manifest_sha256: str | None = None
    manifest_matches: bool | None = None
    metrics: list[ProviderComparison] = Field(default_factory=list)


class BenchmarkCounts(BaseModel):
    """Exact benchmark inventory counts derived from repository manifests."""

    source_samples: int = 0
    binary_samples: int = 0
    fuzz_scenarios: int = 0


class BinaryBenchmarkMetric(BaseModel):
    """One canonical binary benchmark profile metric."""

    method: str
    profile: str
    samples: int = 0
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    false_positive_rate: float = 0.0
    evidence_chain_coverage: float = 0.0
    generated_at: str | None = None


class ElfBenchmarkSummary(BaseModel):
    """Canonical ELF-A inventory, provenance and per-profile results."""

    fixture_count: int = 0
    family_count: int = 0
    profile_count: int = 0
    row_count: int = 0
    compiler_version: str | None = None
    compiler_machine: str | None = None
    target_execution: bool | None = None
    generated_at: str | None = None
    profiles: list[BinaryBenchmarkMetric] = Field(default_factory=list)


class BenchmarkSummary(BaseModel):
    """Front-page benchmark coverage plus the stripped-binary result."""

    counts: BenchmarkCounts = Field(default_factory=BenchmarkCounts)
    stripped_binary: BinaryBenchmarkMetric | None = None
    elf_a: ElfBenchmarkSummary | None = None


class AcceptanceCondition(BaseModel):
    """One named acceptance sub-check with an honest boolean."""

    key: str
    label: str
    met: bool
    detail: str


class AcceptanceTarget(BaseModel):
    """One packed/obfuscated closed-source acceptance target."""

    sample_id: str
    software_name: str
    author: str | None = None
    version: str | None = None
    protection_kind: str
    protector_product: str | None = None
    protector_secondary: str | None = None
    sha256: str | None = None
    file_format: str | None = None
    architecture: str | None = None
    source_uri: str | None = None
    static_analysis_authorized: bool = False
    tool_transform_authorized: bool = False
    dynamic_execution_authorized: bool = False
    material_present: bool = False
    sha256_verified: bool = False
    intake_ready: bool = False
    vulnerability_ground_truth_available: bool = False
    finding_count: int | None = None
    finding_status_counts: dict[str, int] = Field(default_factory=dict)
    evidence_chain_complete: bool | None = None
    static_signals_observed: bool | None = None
    pseudocode_available: bool | None = None
    target_executed: bool = False
    report_links: dict[str, str] = Field(default_factory=dict)
    issues: list[str] = Field(default_factory=list)


class AcceptanceGroup(BaseModel):
    """One of the three course-test groups."""

    group_id: str
    title: str
    status: AcceptanceStatus
    summary: str
    providers: list[ProviderStatus] = Field(default_factory=list)
    targets: list[AcceptanceTarget] = Field(default_factory=list)
    conditions: list[AcceptanceCondition] = Field(default_factory=list)
    comparison: list[ProviderComparison] = Field(default_factory=list)
    latest_run: dict[str, Any] = Field(default_factory=dict)


class AcceptanceOverview(BaseModel):
    """Top-level course-test acceptance matrix."""

    passed_groups: int
    total_groups: int
    status_text: str
    code_version: str
    benchmark_version: str
    benchmark_summary: BenchmarkSummary = Field(default_factory=BenchmarkSummary)
    llm_comparison_summary: LLMComparisonSummary = Field(default_factory=LLMComparisonSummary)
    generated_at: str
    environment: dict[str, Any] = Field(default_factory=dict)
    notices: list[str] = Field(default_factory=list)
    groups: list[AcceptanceGroup] = Field(default_factory=list)
