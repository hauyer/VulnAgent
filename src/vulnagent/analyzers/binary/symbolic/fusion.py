"""V0.9 Symbolic + Autonomous Evidence Fusion: reachability service and
evidence fusion.

``ReachabilityService`` turns a candidate (dangerous callsite) into a
:class:`ReachabilityResult` via the symbolic engine.  ``EvidenceFusionEvaluator``
implements the four fusion relations from the V0.9 chapter — support,
contradiction, independence, runtime proof — over evidence records and
verification results.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnagent.analyzers.binary.symbolic.engine import ReachabilityResult, SymbolicEngine
from vulnagent.contracts import VulnerabilityCandidate


@dataclass(frozen=True, slots=True)
class FusionAssessment:
    """Fusion relation summary for one candidate."""

    candidate_id: str
    support: list[str]
    independence: list[str]
    contradiction: list[str]
    runtime_proof: bool
    summary: str


class ReachabilityService:
    """Resolve a candidate's dangerous callsite address to symbolic reachability."""

    def __init__(self, engine: SymbolicEngine | None = None) -> None:
        self.engine = engine or SymbolicEngine()

    def reach_candidate(
        self, target: Path, candidate: VulnerabilityCandidate
    ) -> ReachabilityResult:
        address = candidate.metadata.get("callsite_address")
        if isinstance(address, str):
            address = int(address, 16)
        if not isinstance(address, int):
            return ReachabilityResult(
                available=True,
                reachable=False,
                target_address=0,
                path_count=0,
                constraint_summary=[],
                reason="no_callsite_address",
            )
        return self.engine.reach(target, address)


class EvidenceFusionEvaluator:
    """Evaluate support / contradiction / independence / runtime proof."""

    _RUNTIME_PROOF_TYPES = {"crash_log", "stack_trace", "sanitizer_output"}
    _PROBATIVE_TYPES = {"source_location", "code_snippet", "disassembly"}

    def assess(
        self,
        *,
        candidate_id: str,
        evidence_types: list[str],
        independent_groups: list[str],
        runtime_proof: bool,
        reachable: bool,
    ) -> FusionAssessment:
        support = [t for t in evidence_types if t in self._PROBATIVE_TYPES]
        runtime = [t for t in evidence_types if t in self._RUNTIME_PROOF_TYPES]
        contradictions: list[str] = []
        if not reachable:
            contradictions.append("symbolic_reachability_unproven")
        if not evidence_types:
            contradictions.append("no_evidence")
        return FusionAssessment(
            candidate_id=candidate_id,
            support=sorted(set(support)),
            independence=sorted(set(independent_groups)),
            contradiction=sorted(set(contradictions)),
            runtime_proof=runtime_proof and bool(runtime),
            summary=(
                f"support={len(support)} independence={len(independent_groups)} "
                f"runtime_proof={bool(runtime)}"
            ),
        )
