"""PUBLIC CONTRACT (new, V0.5): candidate fusion DTOs.

Multiple engines (native auditor, semgrep, joern, ...) commonly rediscover the
same flaw.  The fusion layer normalizes every ``VulnerabilityCandidate`` into a
``CandidateFingerprint`` and groups them into one ``FusedCandidate`` so the
verifier sees one finding backed by several independent sources.
"""
from typing import Any

from pydantic import Field

from .common import ContractModel
from .vulnerability import VulnerabilityLocation, VulnerabilityStatus


class CandidateFingerprint(ContractModel):
    """Stable identity of one underlying flaw across engines.

    ``key`` is the strict five-component fingerprint (CWE + location + sink +
    function + taint source); ``loose_key`` drops function/taint-source, whose
    extraction differs across engines, and is what cross-engine matching uses.
    """

    key: str
    loose_key: str = ""
    cwe_id: str | None = None
    vulnerability_type: str | None = None
    normalized_location: str = ""
    sink: str | None = None
    function: str | None = None
    taint_source: str | None = None
    components: dict[str, Any] = Field(default_factory=dict)


class FusedCandidate(ContractModel):
    """One merged finding backed by one or more source candidates."""

    candidate_id: str
    task_id: str
    vulnerability_type: str
    cwe_id: str | None = None
    primary_location: VulnerabilityLocation | None = None
    source_candidates: list[str] = Field(default_factory=list)
    supporting_independence_groups: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    fused_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: VulnerabilityStatus = VulnerabilityStatus.CANDIDATE
    metadata: dict[str, Any] = Field(default_factory=dict)


__all__ = ["CandidateFingerprint", "FusedCandidate"]
