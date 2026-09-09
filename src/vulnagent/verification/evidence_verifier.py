"""Deterministic, evidence-driven independent verifier (P7 / V0.3 capability).

This is the real (non-Mock) replacement for ``MockVerifier``: it decides a
``VulnerabilityCandidate`` only from the ``Evidence`` supplied in the
``VerificationContext`` and never mutates the candidate.

Rules are deterministic and explainable so a course audience can follow exactly
why a candidate was confirmed, rejected, or left uncertain:

* ``CRASH_LOG`` / ``STACK_TRACE`` / ``SANITIZER_OUTPUT`` at/above the runtime
  reliability threshold prove a reachable runtime fault (``CONFIRMED``).
* ``CONFIRMED`` from static signals requires **at least two distinct probative
  evidence kinds** (each at/above the probative reliability threshold) **and** a
  usable location.  Auxiliary signals (fuzz input, coverage, tool result,
  runtime trace) never count toward confirmation on their own.
* A single probative signal is plausible but under-proven -> ``UNCERTAIN``.
* ``MODEL_REASONING_SUMMARY`` is only ever auxiliary; it can never confirm and
  never raises confidence.
* Confidence is computed only from the evidence that actually drives the verdict
  (never model reasoning, never low-reliability or auxiliary-only signals).
* Candidates without evidence or with broken required fields are ``REJECTED``
  with the reason preserved (never silently dropped).

Only this boundary may emit ``CONFIRMED`` / ``REJECTED`` / ``UNCERTAIN``.
"""

from collections import Counter

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    VerificationContext,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityStatus,
)

# Evidence kinds that alone prove a reachable runtime fault.
_STRONG_RUNTIME = frozenset(
    {
        EvidenceType.CRASH_LOG,
        EvidenceType.STACK_TRACE,
        EvidenceType.SANITIZER_OUTPUT,
    }
)

# Probative static signals.  Only these (at/above threshold) may confirm.
_PROBATIVE_SOURCE = frozenset(
    {
        EvidenceType.SOURCE_LOCATION,
        EvidenceType.CODE_SNIPPET,
        EvidenceType.CALL_PATH,
        EvidenceType.DATA_FLOW,
        EvidenceType.TAINT_PATH,
    }
)
_PROBATIVE_BINARY = frozenset(
    {
        EvidenceType.BINARY_ADDRESS,
        EvidenceType.DISASSEMBLY,
        EvidenceType.CFG_PATH,
    }
)
_PROBATIVE = _PROBATIVE_SOURCE | _PROBATIVE_BINARY

# Contextual signals: they may accompany a verdict but never confirm on their own.
_AUXILIARY = frozenset(
    {
        EvidenceType.FUZZ_INPUT,
        EvidenceType.COVERAGE,
        EvidenceType.RUNTIME_TRACE,
        EvidenceType.TOOL_RESULT,
    }
)

# Model reasoning is never proof by itself and never raises confidence.
_MODEL_ONLY = frozenset({EvidenceType.MODEL_REASONING_SUMMARY})

# Reliability thresholds for probative / runtime evidence.
MIN_PROBATIVE_RELIABILITY = 0.5
MIN_RUNTIME_RELIABILITY = 0.5

_REQUIRED_CANDIDATE_FIELDS = ("title", "description", "source_agent")

_RULE_VERSION = "0.3.1"


def _location_supported(candidate: VulnerabilityCandidate) -> bool:
    """A location is usable when at least one locator is present."""
    location = candidate.location
    if location is None:
        return False
    return bool(
        location.file_path
        or location.binary_address
        or location.module_name
        or location.function_name
    )


def _referenced_evidence(
    candidate: VulnerabilityCandidate,
    context: VerificationContext,
) -> tuple[list[Evidence], list[str]]:
    """Return (resolved, unresolved) evidence ids referenced by the candidate."""
    by_id = {item.evidence_id: item for item in context.evidence}
    resolved: list[Evidence] = []
    unresolved: list[str] = []
    for evidence_id in candidate.evidence_ids:
        item = by_id.get(evidence_id)
        if item is None or item.task_id != candidate.task_id:
            unresolved.append(evidence_id)
        else:
            resolved.append(item)
    return resolved, unresolved


class EvidenceVerifier:
    """Evidence-driven verifier implementing the ``VulnerabilityVerifier`` port."""

    async def verify(
        self,
        candidate: VulnerabilityCandidate,
        context: VerificationContext,
    ) -> VerificationResult:
        evidence_ids: list[str] = []
        resolved, unresolved = _referenced_evidence(candidate, context)

        # 1. Completeness: a malformed candidate cannot be judged.
        missing_fields = [
            field
            for field in _REQUIRED_CANDIDATE_FIELDS
            if not getattr(candidate, field, None)
        ]
        if missing_fields:
            return self._result(
                candidate,
                status=VulnerabilityStatus.REJECTED,
                confidence=0.1,
                rationale=(
                    "Incomplete candidate rejected before verdict: missing "
                    f"required field(s) {', '.join(missing_fields)}."
                ),
                evidence_ids=[],
                counts=Counter(),
                unresolved=unresolved,
                extra={"stage": "completeness"},
            )

        if not resolved:
            return self._result(
                candidate,
                status=VulnerabilityStatus.REJECTED,
                confidence=0.1,
                rationale=(
                    "No verifiable evidence was attached to this candidate; "
                    "it cannot be independently confirmed."
                ),
                evidence_ids=[],
                counts=Counter(),
                unresolved=unresolved,
                extra={"stage": "evidence_missing"},
            )

        counts = Counter(item.evidence_type.value for item in resolved)
        evidence_ids = [item.evidence_id for item in resolved]

        # 2. Runtime proof (only evidence at/above the runtime threshold counts).
        runtime_proof = [
            item
            for item in resolved
            if item.evidence_type in _STRONG_RUNTIME
            and item.reliability >= MIN_RUNTIME_RELIABILITY
        ]
        if runtime_proof:
            return self._result(
                candidate,
                status=VulnerabilityStatus.CONFIRMED,
                confidence=round(
                    min(0.95, 0.5 + _max_reliability(runtime_proof) * 0.5),
                    3,
                ),
                rationale=(
                    "Runtime proof evidence "
                    f"({', '.join(sorted(_unique_types(runtime_proof)))}) supplied "
                    "for the candidate demonstrates a reachable fault; the verdict "
                    "is grounded in that runtime artifact."
                ),
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={"stage": "runtime_proof", "participating_types": _unique_types(runtime_proof)},
            )

        # 3. Probative static signals (each must clear the probative threshold).
        probative = [
            item
            for item in resolved
            if item.evidence_type in _PROBATIVE
            and item.reliability >= MIN_PROBATIVE_RELIABILITY
        ]
        probative_kinds = _unique_types(probative)
        location_ok = _location_supported(candidate)

        if len(probative_kinds) >= 2 and location_ok:
            return self._result(
                candidate,
                status=VulnerabilityStatus.CONFIRMED,
                confidence=round(
                    min(0.9, 0.5 + _max_reliability(probative) * 0.4),
                    3,
                ),
                rationale=(
                    "Independent static corroboration: multiple probative evidence "
                    f"kinds ({', '.join(sorted(probative_kinds))}) at/above the "
                    "reliability threshold agree on a usable candidate location."
                ),
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={
                    "stage": "static_corroboration",
                    "participating_types": probative_kinds,
                },
            )

        if len(probative_kinds) >= 1:
            reason = (
                "Single probative evidence kind "
                f"({', '.join(sorted(probative_kinds))}); candidate is plausible "
                "but under-proven without a second independent signal or runtime "
                "reproduction."
            )
            if not location_ok:
                reason += " The candidate also lacks a usable location."
            return self._result(
                candidate,
                status=VulnerabilityStatus.UNCERTAIN,
                confidence=round(
                    min(0.6, 0.3 + _max_reliability(probative) * 0.5),
                    3,
                ),
                rationale=reason,
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={
                    "stage": "under_proven",
                    "participating_types": probative_kinds,
                },
            )

        # 4. No qualifying probative evidence.
        if any(item.evidence_type in _MODEL_ONLY for item in resolved):
            return self._result(
                candidate,
                status=VulnerabilityStatus.UNCERTAIN,
                confidence=0.2,
                rationale=(
                    "Only model reasoning summary was supplied; model prose "
                    "cannot independently prove a vulnerability and does not "
                    "raise confidence. Awaiting code or runtime corroboration."
                ),
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={"stage": "model_only", "participating_types": []},
            )

        auxiliary_present = any(item.evidence_type in _AUXILIARY for item in resolved)
        if auxiliary_present:
            return self._result(
                candidate,
                status=VulnerabilityStatus.UNCERTAIN,
                confidence=0.2,
                rationale=(
                    "Only auxiliary/contextual signals were supplied (fuzz input, "
                    "coverage, runtime trace or tool result). Auxiliary signals do "
                    "not confirm a vulnerability without qualifying probative or "
                    "runtime evidence."
                ),
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={"stage": "auxiliary_only", "participating_types": []},
            )

        return self._result(
            candidate,
            status=VulnerabilityStatus.UNCERTAIN,
            confidence=0.2,
            rationale=(
                "No probative evidence at/above the reliability threshold was "
                "found among the attached evidence; verdict left uncertain for "
                "human review."
            ),
            evidence_ids=evidence_ids,
            counts=counts,
            unresolved=unresolved,
            extra={"stage": "no_qualifying_evidence", "participating_types": []},
        )

    @staticmethod
    def _result(
        candidate: VulnerabilityCandidate,
        *,
        status: VulnerabilityStatus,
        confidence: float,
        rationale: str,
        evidence_ids: list[str],
        counts: Counter,
        unresolved: list[str],
        extra: dict,
    ) -> VerificationResult:
        """Build a structured verdict without mutating the candidate."""
        metadata = {
            "verifier": "EvidenceVerifier",
            "rule_version": _RULE_VERSION,
            "evidence_counts": dict(counts),
            "unresolved_evidence_ids": unresolved,
            "confidence_band": _confidence_band(confidence),
            **extra,
        }
        return VerificationResult(
            vulnerability_id=candidate.vulnerability_id,
            task_id=candidate.task_id,
            status=status,
            confidence=round(confidence, 3),
            rationale=rationale,
            evidence_ids=evidence_ids,
            metadata=metadata,
        )


def _unique_types(items: list[Evidence]) -> list[str]:
    return sorted({item.evidence_type.value for item in items})


def _max_reliability(items: list[Evidence]) -> float:
    return max((item.reliability for item in items), default=0.0)


def _confidence_band(confidence: float) -> str:
    if confidence >= 0.9:
        return "very_high"
    if confidence >= 0.7:
        return "high"
    if confidence >= 0.4:
        return "medium"
    return "low"
