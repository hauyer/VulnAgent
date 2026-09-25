"""WP5: benchmark adapters.

``ExploitGymDiscoveryAdapter`` implements the adaptation screening protocol
from the development guide: a task qualifies for the *custom discovery* track
only when the answer can be fully hidden and the target can be fixed and run
locally; otherwise it is recorded as a case-study-only item, never as a blind
discovery result. ``VulnGymCatalogBuilder`` partitions verified project items
into dev / held-out sets (same project never crosses the split).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vulnagent.benchmark.schema import (
    BlindCaseManifest,
    BlindEligibility,
    Role,
)


@dataclass(slots=True)
class ScreeningRecord:
    task_id: str
    eligibility: BlindEligibility
    reasons: list[str] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)


@dataclass(slots=True)
class ExploitGymDiscoveryAdapter:
    """Screening adapter for the custom ExploitGym discovery protocol.

    Non-official by design: the guide forbids presenting adapted runs as
    official ExploitGym discovery scores.
    """

    def screen(
        self,
        task_id: str,
        *,
        local_target_fixed: bool,
        ground_truth_detachable: bool,
        answer_hidden: bool,
        safe_to_run: bool,
        notes: str = "",
    ) -> ScreeningRecord:
        reasons: list[str] = []
        checks = {
            "local_target_fixed": local_target_fixed,
            "ground_truth_detachable": ground_truth_detachable,
            "answer_hidden": answer_hidden,
            "safe_to_run": safe_to_run,
        }
        if not (local_target_fixed and ground_truth_detachable):
            reasons.append("target or ground truth cannot be fixed locally")
        if not answer_hidden:
            reasons.append(
                "answer (location/description/patch/trigger) visible to agent"
            )
        if not safe_to_run:
            reasons.append("cannot be sandboxed safely")

        eligibility = (
            BlindEligibility.ELIGIBLE
            if not reasons
            else (
                BlindEligibility.UNSAFE
                if "cannot be sandboxed safely" in reasons
                else BlindEligibility.NOT_BLIND
            )
        )
        if notes:
            reasons.append(notes)
        return ScreeningRecord(
            task_id=task_id,
            eligibility=eligibility,
            reasons=reasons,
            checks=checks,
        )


@dataclass(slots=True)
class VulnGymCatalogBuilder:
    """Partitions verified VulnGym project items into dev / held-out sets.

    Rule: a project's items all live in one partition -- neighbouring
    versions of the same project never cross dev and held-out.
    """

    def partition(
        self,
        items: list[dict],
        held_out_projects: set[str],
    ) -> dict[Role, list[dict]]:
        dev: list[dict] = []
        held: list[dict] = []
        for item in items:
            project = str(item["project"])
            if project in held_out_projects:
                held.append(item)
            else:
                dev.append(item)
        return {Role.DEV: dev, Role.HELD_OUT: held}
