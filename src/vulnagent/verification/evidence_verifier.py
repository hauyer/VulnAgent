"""Deterministic, evidence-driven independent verifier (P7 / V0.3 capability).

This is the real (non-Mock) replacement for ``MockVerifier``: it decides a
``VulnerabilityCandidate`` only from the ``Evidence`` supplied in the
``VerificationContext`` and never mutates the candidate.

Rules are intentionally deterministic and explainable so a course audience can
follow exactly why a candidate was confirmed, rejected, or left uncertain:

* ``CRASH_LOG`` / ``STACK_TRACE`` / ``SANITIZER_OUTPUT`` evidence proves a
  reachable runtime fault on its own (``CONFIRMED``).
* Static corroboration needs at least two independent evidence kinds
  (e.g. ``SOURCE_LOCATION`` + ``CODE_SNIPPET`` or ``CALL_PATH``/``TAINT_PATH``)
  **and** a usable location before the candidate may be ``CONFIRMED``.
* A single static signal is plausible but under-proven -> ``UNCERTAIN``.
* ``MODEL_REASONING_SUMMARY`` is only ever auxiliary; it can never confirm.
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

# Kinds that alone prove a reachable runtime fault.
_STRONG_RUNTIME = frozenset(
    {
        EvidenceType.CRASH_LOG,
        EvidenceType.STACK_TRACE,
        EvidenceType.SANITIZER_OUTPUT,
    }
)

# Static source signals that corroborate a candidate.
_STATIC_SOURCE = frozenset(
    {
        EvidenceType.SOURCE_LOCATION,
        EvidenceType.CODE_SNIPPET,
        EvidenceType.CALL_PATH,
        EvidenceType.DATA_FLOW,
        EvidenceType.TAINT_PATH,
    }
)

# Static binary signals that corroborate a candidate.
_STATIC_BINARY = frozenset(
    {
        EvidenceType.BINARY_ADDRESS,
        EvidenceType.DISASSEMBLY,
        EvidenceType.CFG_PATH,
    }
)

# Contextual, but not on their own probative, signals.
_AUXILIARY = frozenset(
    {
        EvidenceType.FUZZ_INPUT,
        EvidenceType.COVERAGE,
        EvidenceType.RUNTIME_TRACE,
        EvidenceType.TOOL_RESULT,
    }
)

# Model reasoning is never proof by itself.
_MODEL_ONLY = frozenset({EvidenceType.MODEL_REASONING_SUMMARY})

# Everything that can positively corroborate a candidate.
_CORROBORATING = _STATIC_SOURCE | _STATIC_BINARY | _AUXILIARY | _STRONG_RUNTIME

_REQUIRED_CANDIDATE_FIELDS = ("title", "description", "source_agent")

_RULE_VERSION = "0.3.0"


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


def _max_reliability(items: list[Evidence]) -> float:
    return max((item.reliability for item in items), default=0.0)


class EvidenceVerifier:
    """Evidence-driven verifier implementing the ``VulnerabilityVerifier`` port."""

    async def verify(
        self,
        candidate: VulnerabilityCandidate,
        context: VerificationContext,
    ) -> VerificationResult:
        evidence_ids: list[str] = []
        counts: Counter[str] = Counter()
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
                counts=counts,
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
                    "it cannot be independently confirmed or reproduced."
                ),
                evidence_ids=[],
                counts=counts,
                unresolved=unresolved,
                extra={"stage": "evidence_missing"},
            )

        counts = Counter(item.evidence_type.value for item in resolved)
        for item in resolved:
            evidence_ids.append(item.evidence_id)

        runtime_kinds = {
            item.evidence_type for item in resolved if item.evidence_type in _STRONG_RUNTIME
        }
        if runtime_kinds:
            return self._result(
                candidate,
                status=VulnerabilityStatus.CONFIRMED,
                confidence=round(min(0.95, 0.5 + _max_reliability(resolved) * 0.5), 3),
                rationale=(
                    "Runtime proof present: reachable crash/stack/sanitizer "
                    "evidence was independently reproduced and confirms the "
                    f"candidate ({', '.join(sorted(k.value for k in runtime_kinds))})."
                ),
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={"stage": "runtime_proof"},
            )

        # Corroborating static/contextual evidence (model reasoning excluded).
        corroborating = {
            item.evidence_type
            for item in resolved
            if item.evidence_type in _CORROBORATING
        }
        kind_count = len(corroborating)
        location_ok = _location_supported(candidate)

        if kind_count >= 2 and location_ok:
            return self._result(
                candidate,
                status=VulnerabilityStatus.CONFIRMED,
                confidence=round(min(0.9, 0.5 + _max_reliability(resolved) * 0.4), 3),
                rationale=(
                    "Independent static corroboration: multiple evidence kinds "
                    f"({', '.join(sorted(k.value for k in corroborating))}) agree "
                    "on a usable candidate location."
                ),
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={"stage": "static_corroboration"},
            )

        if kind_count >= 1:
            reason = (
                "Single evidence kind present "
                f"({', '.join(sorted(k.value for k in corroborating))}); "
                "candidate is plausible but under-proven without a second "
                "independent signal or runtime reproduction."
            )
            if not location_ok:
                reason += " The candidate also lacks a usable location."
            return self._result(
                candidate,
                status=VulnerabilityStatus.UNCERTAIN,
                confidence=round(min(0.6, 0.3 + _max_reliability(resolved) * 0.5), 3),
                rationale=reason,
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={"stage": "under_proven"},
            )

        model_only = {
            item.evidence_type
            for item in resolved
            if item.evidence_type in _MODEL_ONLY
        }
        if model_only:
            return self._result(
                candidate,
                status=VulnerabilityStatus.UNCERTAIN,
                confidence=0.2,
                rationale=(
                    "Only model reasoning summary was supplied; model prose "
                    "cannot independently prove a vulnerability. Awaiting code "
                    "or runtime corroboration."
                ),
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={"stage": "model_only"},
            )

        return self._result(
            candidate,
            status=VulnerabilityStatus.UNCERTAIN,
            confidence=0.2,
            rationale=(
                "No probative evidence kind was found among the attached "
                "evidence; verdict left uncertain for human review."
            ),
            evidence_ids=evidence_ids,
            counts=counts,
            unresolved=unresolved,
            extra={"stage": "no_probative_evidence"},
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


def _confidence_band(confidence: float) -> str:
    if confidence >= 0.9:
        return "very_high"
    if confidence >= 0.7:
        return "high"
    if confidence >= 0.4:
        return "medium"
    return "low"
