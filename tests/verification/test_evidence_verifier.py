"""Unit tests for P7 EvidenceVerifier (deterministic, evidence-driven verdicts)."""

import pytest

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    VerificationContext,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)
from vulnagent.verification.evidence_verifier import EvidenceVerifier

TASK_ID = "task-1"


def make_candidate(vulnerability_id: str = "v1", *, evidence_ids: list[str] | None = None, title: str = "Potential command injection", location: VulnerabilityLocation | None = None) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id=vulnerability_id,
        task_id=TASK_ID,
        title=title,
        vulnerability_type="command_injection",
        description="User input may reach an unsafe sink.",
        target_id="target-1",
        location=location or VulnerabilityLocation(file_path="a.c", function_name="parse", line_start=1, line_end=2),
        source_agent="source_audit",
        source_type="source",
        confidence=0.6,
        severity="HIGH",
        evidence_ids=evidence_ids or [],
    )


def make_evidence(evidence_id: str, evidence_type: EvidenceType, *, reliability: float = 0.6) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        task_id=TASK_ID,
        evidence_type=evidence_type,
        source="source_audit",
        description=f"{evidence_type.value} evidence",
        reliability=reliability,
        created_by="source_audit",
    )


async def verify(candidate: VulnerabilityCandidate, evidence: list[Evidence]) -> VerificationResult:
    verifier = EvidenceVerifier()
    return await verifier.verify(candidate, VerificationContext(task_id=TASK_ID, evidence=evidence))


async def test_model_reasoning_alone_cannot_confirm() -> None:
    evidence = [make_evidence("e1", EvidenceType.MODEL_REASONING_SUMMARY, reliability=0.5)]
    candidate = make_candidate(evidence_ids=["e1"])
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.UNCERTAIN
    assert "model reasoning" in result.rationale


async def test_candidate_without_evidence_is_rejected() -> None:
    candidate = make_candidate(evidence_ids=[])
    result = await verify(candidate, [])
    assert result.status is VulnerabilityStatus.REJECTED
    assert result.rationale


async def test_candidate_with_unresolved_evidence_is_rejected() -> None:
    # References an evidence id that is not present in the context.
    candidate = make_candidate(evidence_ids=["missing"])
    result = await verify(candidate, [])
    assert result.status is VulnerabilityStatus.REJECTED
    assert result.metadata["unresolved_evidence_ids"] == ["missing"]


async def test_missing_required_field_is_rejected() -> None:
    evidence = [make_evidence("e1", EvidenceType.SOURCE_LOCATION)]
    candidate = make_candidate(evidence_ids=["e1"], title="")
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.REJECTED
    assert result.metadata["stage"] == "completeness"


async def test_single_static_signal_is_uncertain() -> None:
    evidence = [make_evidence("e1", EvidenceType.SOURCE_LOCATION, reliability=0.5)]
    candidate = make_candidate(evidence_ids=["e1"])
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.UNCERTAIN
    assert result.metadata["stage"] == "under_proven"


async def test_model_plus_single_code_snippet_is_still_uncertain() -> None:
    evidence = [
        make_evidence("e1", EvidenceType.MODEL_REASONING_SUMMARY, reliability=0.5),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, reliability=0.5),
    ]
    candidate = make_candidate(evidence_ids=["e1", "e2"])
    result = await verify(candidate, evidence)
    # Only CODE_SNIPPET is corroborating -> one kind -> under-proven.
    assert result.status is VulnerabilityStatus.UNCERTAIN


async def test_multikind_source_corroboration_confirms() -> None:
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, reliability=0.6),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, reliability=0.7),
        make_evidence("e3", EvidenceType.CALL_PATH, reliability=0.7),
    ]
    candidate = make_candidate(evidence_ids=["e1", "e2", "e3"])
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    assert result.metadata["stage"] == "static_corroboration"
    assert result.confidence >= 0.5


async def test_runtime_crash_alone_confirms() -> None:
    evidence = [make_evidence("e1", EvidenceType.CRASH_LOG, reliability=0.95)]
    candidate = make_candidate(evidence_ids=["e1"])
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    assert result.metadata["stage"] == "runtime_proof"
    assert result.confidence >= 0.9


async def test_verifier_never_mutates_candidate() -> None:
    evidence = [make_evidence("e1", EvidenceType.CODE_SNIPPET, reliability=0.7)]
    candidate = make_candidate(evidence_ids=["e1"])
    await verify(candidate, evidence)
    assert candidate.status is VulnerabilityStatus.CANDIDATE
    assert candidate.evidence_ids == ["e1"]


async def test_result_carries_rationale_and_evidence_refs() -> None:
    evidence = [make_evidence("e1", EvidenceType.CRASH_LOG, reliability=0.9)]
    candidate = make_candidate(evidence_ids=["e1"])
    result = await verify(candidate, evidence)
    assert result.rationale
    assert result.evidence_ids == ["e1"]
    assert result.metadata["evidence_counts"] == {"crash_log": 1}
    assert result.metadata["verifier"] == "EvidenceVerifier"


async def test_auxiliary_evidence_alone_does_not_confirm() -> None:
    # Three auxiliary signals (no probative kind) must never reach CONFIRMED.
    evidence = [
        make_evidence("e1", EvidenceType.FUZZ_INPUT, reliability=0.7),
        make_evidence("e2", EvidenceType.COVERAGE, reliability=0.8),
        make_evidence("e3", EvidenceType.TOOL_RESULT, reliability=0.8),
    ]
    candidate = make_candidate(evidence_ids=["e1", "e2", "e3"])
    result = await verify(candidate, evidence)
    assert result.status is not VulnerabilityStatus.CONFIRMED
    assert result.status is VulnerabilityStatus.UNCERTAIN
    assert result.metadata["stage"] == "auxiliary_only"


async def test_low_reliability_probative_does_not_confirm() -> None:
    # Probative evidence below the reliability threshold does not count.
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, reliability=0.2),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, reliability=0.2),
    ]
    candidate = make_candidate(evidence_ids=["e1", "e2"])
    result = await verify(candidate, evidence)
    assert result.status is not VulnerabilityStatus.CONFIRMED
    assert result.metadata["stage"] == "no_qualifying_evidence"


async def test_probative_at_threshold_plus_auxiliary_still_confirms() -> None:
    # Two probative kinds above threshold confirm even when auxiliary is present.
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, reliability=0.6),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, reliability=0.7),
        make_evidence("e3", EvidenceType.COVERAGE, reliability=0.9),
    ]
    candidate = make_candidate(evidence_ids=["e1", "e2", "e3"])
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    assert result.metadata["participating_types"] == ["code_snippet", "source_location"]


async def test_model_summary_does_not_raise_confidence() -> None:
    # Confidence must come only from evidence that drives the verdict; model
    # reasoning must not indirectly boost it.
    without_model = [make_evidence("e1", EvidenceType.CODE_SNIPPET, reliability=0.7)]
    with_model = [
        make_evidence("e1", EvidenceType.CODE_SNIPPET, reliability=0.7),
        make_evidence("e2", EvidenceType.MODEL_REASONING_SUMMARY, reliability=0.9),
    ]
    result_plain = await verify(make_candidate(evidence_ids=["e1"]), without_model)
    result_model = await verify(make_candidate(evidence_ids=["e1", "e2"]), with_model)
    assert result_plain.confidence == result_model.confidence
    assert result_plain.confidence < 0.7  # single probative kind stays low/medium


async def test_runtime_rationale_does_not_claim_independent_reproduction() -> None:
    evidence = [make_evidence("e1", EvidenceType.SANITIZER_OUTPUT, reliability=0.9)]
    candidate = make_candidate(evidence_ids=["e1"])
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    assert "independently reproduced" not in result.rationale
    assert "reproduced" not in result.rationale
