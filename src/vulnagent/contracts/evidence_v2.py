"""Evidence V2 DTO with provenance support (V0.5 Evidence Provenance).

The legacy ``Evidence`` contract stays frozen; V2 adds the fields needed to
answer "which tool produced this, from which run, which derivation, and which
independence group".  New producers write ``EvidenceV2``; ``to_legacy()`` maps
it onto the frozen ``Evidence`` shape with the provenance carried in
``data["provenance"]`` so the existing storage/verification boundary keeps
working unchanged.
"""
from datetime import datetime
from typing import Any

from pydantic import Field

from .common import ContractModel, utc_now
from .evidence import Evidence, EvidenceType


class EvidenceV2(ContractModel):
    """Canonical evidence DTO for the V0.5+ evidence chain.

    Fields follow the V1.0 blueprint (docs, section 14.2):

    * ``analysis_run_id``   — the single tool execution run that produced it.
    * ``derivation_id``     — all evidence pieces emitted by one rule firing
      (e.g. SOURCE_LOCATION + CODE_SNIPPET + TAINT_PATH) share one id.
    * ``independence_group``— the independent analysis family (native-taint,
      semgrep, joern, ghidra, asan, angr, ...); the verifier counts distinct
      groups, not distinct evidence types.
    """

    evidence_id: str
    task_id: str
    session_id: str | None = None
    evidence_type: EvidenceType
    producer: str
    producer_version: str | None = None
    analysis_run_id: str | None = None
    derivation_id: str | None = None
    independence_group: str | None = None
    parent_evidence_ids: list[str] = Field(default_factory=list)
    subject_ids: list[str] = Field(default_factory=list)
    reliability: float = Field(ge=0.0, le=1.0)
    artifact_refs: list[str] = Field(default_factory=list)
    description: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    def to_legacy(self) -> Evidence:
        """Map onto the frozen public ``Evidence`` DTO without losing provenance."""
        provenance: dict[str, Any] = {"producer": self.producer}
        if self.producer_version is not None:
            provenance["producer_version"] = self.producer_version
        if self.session_id is not None:
            provenance["session_id"] = self.session_id
        if self.analysis_run_id is not None:
            provenance["analysis_run_id"] = self.analysis_run_id
        if self.derivation_id is not None:
            provenance["derivation_id"] = self.derivation_id
        if self.independence_group is not None:
            provenance["independence_group"] = self.independence_group
        if self.parent_evidence_ids:
            provenance["parent_evidence_ids"] = list(self.parent_evidence_ids)
        if self.subject_ids:
            provenance["subject_ids"] = list(self.subject_ids)
        if self.artifact_refs:
            provenance["artifact_refs"] = list(self.artifact_refs)

        data = dict(self.data)
        data["provenance"] = provenance
        return Evidence(
            evidence_id=self.evidence_id,
            task_id=self.task_id,
            evidence_type=self.evidence_type,
            source=self.producer,
            description=self.description or self.evidence_type.value,
            data=data,
            reliability=self.reliability,
            created_by=self.producer,
            created_at=self.created_at,
        )

    @classmethod
    def from_evidence(cls, evidence: Evidence) -> "EvidenceV2":
        """Rebuild a V2 DTO from a stored legacy evidence, if possible."""
        provenance = evidence.data.get("provenance", {})
        if not isinstance(provenance, dict):
            provenance = {}
        return cls(
            evidence_id=evidence.evidence_id,
            task_id=evidence.task_id,
            session_id=provenance.get("session_id"),
            evidence_type=evidence.evidence_type,
            producer=str(provenance.get("producer") or evidence.created_by or evidence.source),
            producer_version=provenance.get("producer_version"),
            analysis_run_id=provenance.get("analysis_run_id"),
            derivation_id=provenance.get("derivation_id"),
            independence_group=provenance.get("independence_group"),
            parent_evidence_ids=list(provenance.get("parent_evidence_ids") or []),
            subject_ids=list(provenance.get("subject_ids") or []),
            reliability=evidence.reliability,
            artifact_refs=list(provenance.get("artifact_refs") or []),
            description=evidence.description,
            data=dict(evidence.data),
            created_at=evidence.created_at,
        )


__all__ = ["EvidenceV2"]
