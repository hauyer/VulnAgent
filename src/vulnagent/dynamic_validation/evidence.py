"""Adapter from internal robustness records to the unified Evidence contract."""

from __future__ import annotations

from vulnagent.contracts import Evidence, EvidenceType
from vulnagent.utils.ids import new_evidence_id

from .models import RobustnessRun


def robustness_evidence(
    *,
    task_id: str,
    finding_id: str,
    run: RobustnessRun,
) -> Evidence:
    """Create a redacted runtime record linked to one candidate."""

    return Evidence(
        evidence_id=new_evidence_id(),
        task_id=task_id,
        evidence_type=EvidenceType.RUNTIME_TRACE,
        source="controlled_robustness",
        description="Local sandbox robustness observations with raw inputs and bodies omitted.",
        data={"finding_id": finding_id, **run.public_record()},
        reliability=0.85 if run.reset_completed else 0.5,
        created_by="controlled_robustness",
    )
