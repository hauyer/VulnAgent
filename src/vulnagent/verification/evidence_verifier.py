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
  never raises confidence.  A candidate whose root cause rests ONLY on model
  reasoning is ``REJECTED`` (guard: root cause never from model prose).
* Confidence is computed only from the evidence that actually drives the verdict
  (never model reasoning, never low-reliability or auxiliary-only signals).
* Candidates without evidence or with broken required fields are ``REJECTED``
  with the reason preserved (never silently dropped).

S3 layered semantics (strategy ``layered-v1``): every verdict evaluates the
candidate against three explicit layers and records each layer's outcome in
``metadata["layers"]``:

* ``observed_fault``          - a reachable runtime fault artifact exists.
* ``root_cause_supported``    - >=2 independent probative sources + usable location.
* ``security_impact_supported`` - probative taint/data-flow/call-path reaches a
  localized sink (impact alone never confirms).

Guards: memory-fault classes (null deref, OOB, UAF, ...) may only confirm via
``observed_fault`` or ``root_cause_supported``; root cause never originates
from model reasoning; verification downgrades confidence along the chain
observed -> root-cause -> impact -> uncertain and never invents a status.

Only this boundary may emit ``CONFIRMED`` / ``REJECTED`` / ``UNCERTAIN``.
"""

from collections import Counter
from enum import Enum

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    VerificationContext,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityStatus,
)
from vulnagent.verification.independence import EvidenceIndependenceEvaluator

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

# Security-impact evidence kinds: they show entry reachability / flow to a
# dangerous operation; impact alone never confirms.
_IMPACT_KINDS = frozenset(
    {EvidenceType.TAINT_PATH, EvidenceType.DATA_FLOW, EvidenceType.CALL_PATH}
)

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

# Memory-fault classes: confirmation requires observed_fault or
# root_cause_supported (never impact or auxiliary signals alone).
_MEMORY_FAULT_CWES = frozenset(
    {
        "CWE-476",  # NULL pointer dereference
        "CWE-787",  # out-of-bounds write
        "CWE-125",  # out-of-bounds read
        "CWE-416",  # use after free
        "CWE-415",  # double free
        "CWE-761",  # free of pointer not at start
        "CWE-122",  # heap buffer overflow
        "CWE-123",  # write-what-where
        "CWE-690",  # unchecked return to null
        "CWE-119",  # improper restriction of operations
    }
)

_RULE_VERSION = "0.6.0"
_STRATEGY_VERSION = "layered-v1"


class VerificationLayer(str, Enum):
    """S3: the three evidence layers every verdict is graded against."""

    OBSERVED_FAULT = "observed_fault"
    ROOT_CAUSE_SUPPORTED = "root_cause_supported"
    SECURITY_IMPACT_SUPPORTED = "security_impact_supported"


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


def _memory_fault_class(candidate: VulnerabilityCandidate) -> bool:
    cwe = (candidate.cwe_id or "").upper()
    return cwe in _MEMORY_FAULT_CWES


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

    def __init__(
        self,
        *,
        strategy_version: str = _STRATEGY_VERSION,
    ) -> None:
        self.strategy_version = strategy_version
        self._independence = EvidenceIndependenceEvaluator()

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

        # 2. Guard: root cause must never rest on model reasoning alone.
        if all(item.evidence_type in _MODEL_ONLY for item in resolved):
            return self._result(
                candidate,
                status=VulnerabilityStatus.REJECTED,
                confidence=0.1,
                rationale=(
                    "Guard: root cause rests only on model reasoning.  Model "
                    "prose cannot independently prove a vulnerability and does "
                    "not raise confidence; awaiting code or runtime evidence."
                ),
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={
                    "stage": "guard_model_reasoning",
                    "layers": {
                        VerificationLayer.OBSERVED_FAULT.value: False,
                        VerificationLayer.ROOT_CAUSE_SUPPORTED.value: False,
                        VerificationLayer.SECURITY_IMPACT_SUPPORTED.value: False,
                    },
                },
            )

        # 3. Layer evaluation (S3): runtime proof, probative corroboration and
        #    security-impact signals, each with its own threshold.
        runtime_proof = [
            item
            for item in resolved
            if item.evidence_type in _STRONG_RUNTIME
            and item.reliability >= MIN_RUNTIME_RELIABILITY
        ]
        probative = [
            item
            for item in resolved
            if item.evidence_type in _PROBATIVE
            and item.reliability >= MIN_PROBATIVE_RELIABILITY
        ]
        probative_kinds = _unique_types(probative)
        independent_sources = self._independence.independent_sources(probative)
        independent_count = len(independent_sources)
        location_ok = _location_supported(candidate)
        impact_present = any(item.evidence_type in _IMPACT_KINDS for item in probative)

        layers = {
            VerificationLayer.OBSERVED_FAULT.value: bool(runtime_proof),
            VerificationLayer.ROOT_CAUSE_SUPPORTED.value: (
                independent_count >= 2 and location_ok
            ),
            VerificationLayer.SECURITY_IMPACT_SUPPORTED.value: (
                impact_present and location_ok
            ),
        }

        # 4. Runtime proof (observed fault): strongest layer, confirms.
        if runtime_proof:
            return self._result(
                candidate,
                status=VulnerabilityStatus.CONFIRMED,
                confidence=round(
                    min(0.95, 0.5 + _max_reliability(runtime_proof) * 0.5),
                    3,
                ),
                rationale=(
                    "Layer observed_fault: runtime proof evidence "
                    f"({', '.join(sorted(_unique_types(runtime_proof)))}) supplied "
                    "for the candidate demonstrates a reachable fault; the verdict "
                    "is grounded in that runtime artifact."
                ),
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={
                    "stage": "runtime_proof",
                    "participating_types": _unique_types(runtime_proof),
                    "independent_sources": self._independence.independent_sources(runtime_proof),
                    "layers": layers,
                },
            )

        # 5. Root-cause corroboration (>=2 independent probative sources +
        #    usable location).  Guard: memory-fault classes confirm exactly here
        #    (or via observed_fault), never via impact/auxiliary alone.
        if independent_count >= 2 and location_ok:
            return self._result(
                candidate,
                status=VulnerabilityStatus.CONFIRMED,
                confidence=round(
                    min(0.9, 0.5 + _max_reliability(probative) * 0.4),
                    3,
                ),
                rationale=(
                    "Layer root_cause_supported: multiple probative evidence "
                    f"kinds ({', '.join(sorted(probative_kinds))}) from "
                    f"{independent_count} independent analysis sources at/above the "
                    "reliability threshold agree on a usable candidate location."
                    + (
                        " Security-impact layer additionally supported by "
                        "taint/data-flow/call-path to the localized sink."
                        if layers[VerificationLayer.SECURITY_IMPACT_SUPPORTED.value]
                        else ""
                    )
                ),
                evidence_ids=evidence_ids,
                counts=counts,
                unresolved=unresolved,
                extra={
                    "stage": "static_corroboration",
                    "participating_types": probative_kinds,
                    "independent_sources": independent_sources,
                    "independent_count": independent_count,
                    "layers": layers,
                },
            )

        # 6. Single independent probative source -> plausible but under-proven.
        if independent_count >= 1:
            reason = (
                "Layer root_cause_supported not satisfied: single independent "
                f"probative source ({', '.join(sorted(probative_kinds))}); "
                "candidate is plausible but under-proven without a second "
                "independent signal or runtime reproduction."
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
                    "independent_sources": independent_sources,
                    "independent_count": independent_count,
                    "layers": layers,
                },
            )

        # 7. No qualifying probative evidence (only model/auxiliary).
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
                extra={
                    "stage": "auxiliary_only",
                    "participating_types": [],
                    "layers": layers,
                },
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
            extra={
                "stage": "no_qualifying_evidence",
                "participating_types": [],
                "layers": layers,
            },
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
            "strategy_version": _STRATEGY_VERSION,
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
