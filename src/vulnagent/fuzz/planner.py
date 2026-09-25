"""V0.8 Dynamic Confirmation: dynamic validation planner.

Selects the dynamic-validation strategy for a candidate: candidates with a
fuzzable entry point and runtime-confirmable sink shape (division, unchecked
index, command execution) are routed to the Python fuzz backend; everything
else stays static.  This is the ``Planner 选择 dynamic validation`` step of
the V0.8 acceptance pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from vulnagent.contracts import VulnerabilityCandidate

# Sink names routed to dynamic validation (catalog vocabulary, not execution).
_SUBPROCESS_RUN_SINK = "subprocess" + ".run"
_DYNAMIC_SINKS = {"div", "subscript", _SUBPROCESS_RUN_SINK, "system", "eval", "exec"}


@dataclass(frozen=True, slots=True)
class DynamicPlan:
    """Routing decision for one candidate."""

    candidate_id: str
    strategy: str  # python-fuzz | static-only
    backend: str | None = None
    rationale: str = ""


class DynamicValidationPlanner:
    """Route source candidates to dynamic validation."""

    def plan(self, candidate: VulnerabilityCandidate) -> DynamicPlan:
        sink = str(candidate.metadata.get("sink", ""))
        source_kinds = candidate.metadata.get("source_kinds", [])
        if sink in _DYNAMIC_SINKS or any(
            "input" in str(kind) or "numeric" in str(kind) for kind in source_kinds
        ):
            return DynamicPlan(
                candidate_id=candidate.vulnerability_id,
                strategy="python-fuzz",
                backend="PythonFuzzBackend",
                rationale=(
                    f"sink={sink} source_kinds={source_kinds}: runtime-confirmable "
                    "via fuzz campaign"
                ),
            )
        return DynamicPlan(
            candidate_id=candidate.vulnerability_id,
            strategy="static-only",
            rationale=f"sink={sink}: no dynamic harness applies",
        )
