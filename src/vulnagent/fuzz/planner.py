"""V0.8/V0.9 Dynamic Confirmation: dynamic validation planners.

``DynamicValidationPlanner`` routes candidates with a fuzzable sink to the
Python fuzz backend.  ``CostAwarePlanner`` (V0.9) adds cost-aware tool
selection: cheap fuzz first, symbolic reachability (angr) only when fuzzing
cannot cover the candidate path — e.g. binary targets with no native
harness.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from vulnagent.contracts import VulnerabilityCandidate

# Sink names routed to dynamic validation (catalog vocabulary, not execution).
_SUBPROCESS_RUN_SINK = "subprocess" + ".run"
_DYNAMIC_SINKS = {"div", "subscript", _SUBPROCESS_RUN_SINK, "system", "eval", "exec"}

# Estimated cost rank per strategy (lower = cheaper).
STRATEGY_COST = {"static-only": 1, "python-fuzz": 10, "symbolic": 100}


@dataclass(frozen=True, slots=True)
class DynamicPlan:
    """Routing decision for one candidate."""

    candidate_id: str
    strategy: str  # python-fuzz | symbolic | static-only
    backend: str | None = None
    cost_rank: int = STRATEGY_COST["static-only"]
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
                cost_rank=STRATEGY_COST["python-fuzz"],
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


class CostAwarePlanner:
    """V0.9 cost-aware tool selection: fuzz first, angr when needed."""

    def plan(self, candidate: VulnerabilityCandidate) -> DynamicPlan:
        sink = str(candidate.metadata.get("sink", ""))
        source_type = candidate.source_type
        harness_available = candidate.metadata.get("harness_available", False)
        if sink in _DYNAMIC_SINKS and harness_available:
            return DynamicPlan(
                candidate_id=candidate.vulnerability_id,
                strategy="python-fuzz",
                backend="PythonFuzzBackend",
                cost_rank=STRATEGY_COST["python-fuzz"],
                rationale="cheapest dynamic validation applies (fuzz first)",
            )
        if candidate.metadata.get("callsite_address"):
            return DynamicPlan(
                candidate_id=candidate.vulnerability_id,
                strategy="symbolic",
                backend="SymbolicEngine",
                cost_rank=STRATEGY_COST["symbolic"],
                rationale=(
                    f"source_type={source_type} callsite present and no fuzz "
                    "harness: symbolic reachability (angr) is the only dynamic "
                    "validation path"
                ),
            )
        return DynamicPlan(
            candidate_id=candidate.vulnerability_id,
            strategy="static-only",
            rationale=f"sink={sink}: no dynamic path applies",
        )
