"""S3 unit: layered evidence-verifier semantics.

Covers the three layers (observed_fault / root_cause_supported /
security_impact_supported), the guard semantics (memory-fault classes,
root cause never from model reasoning, impact alone never confirms) and
strategy versioning.
"""

from __future__ import annotations

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    VerificationContext,
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)
from vulnagent.verification.evidence_verifier import (
    EvidenceVerifier,
    VerificationLayer,
)

TASK_ID = "task-s3"


def make_candidate(
    *,
    cwe_id: str | None = None,
    location: VulnerabilityLocation | None = None,
    evidence_ids: list[str] | None = None,
) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id="v-s3",
        task_id=TASK_ID,
        title="Potential unsafe operation",
        vulnerability_type="memory_corruption",
        description="Evidence-driven candidate for S3 layering.",
        target_id="target-1",
        location=location or VulnerabilityLocation(file_path="a.c", line_start=1),
        source_agent="source_audit",
        source_type="source",
        confidence=0.6,
        severity="HIGH",
        cwe_id=cwe_id,
        evidence_ids=evidence_ids or [],
    )


def make_evidence(
    evidence_id: str,
    evidence_type: EvidenceType,
    *,
    reliability: float = 0.7,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        task_id=TASK_ID,
        evidence_type=evidence_type,
        source="source_audit",
        description=f"{evidence_type.value} evidence",
        reliability=reliability,
        created_by="source_audit",
    )


async def _verify(
    candidate: VulnerabilityCandidate,
    evidence: list[Evidence],
) -> object:
    verifier = EvidenceVerifier()
    return await verifier.verify(
        candidate, VerificationContext(task_id=TASK_ID, evidence=evidence)
    )


def _layers(result) -> dict[str, bool]:
    return result.metadata["layers"]


async def test_observed_fault_layer_confirms() -> None:
    evidence = [make_evidence("e1", EvidenceType.CRASH_LOG, reliability=0.95)]
    candidate = make_candidate(evidence_ids=["e1"])
    result = await _verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    assert result.metadata["stage"] == "runtime_proof"
    assert _layers(result) == {
        VerificationLayer.OBSERVED_FAULT.value: True,
        VerificationLayer.ROOT_CAUSE_SUPPORTED.value: False,
        VerificationLayer.SECURITY_IMPACT_SUPPORTED.value: False,
    }
    assert result.metadata["strategy_version"] == "layered-v1"


async def test_root_cause_layer_confirms() -> None:
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, reliability=0.6),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, reliability=0.7),
    ]
    candidate = make_candidate(evidence_ids=["e1", "e2"])
    result = await _verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    assert result.metadata["stage"] == "static_corroboration"
    layers = _layers(result)
    assert layers[VerificationLayer.OBSERVED_FAULT.value] is False
    assert layers[VerificationLayer.ROOT_CAUSE_SUPPORTED.value] is True


async def test_security_impact_layer_added_but_never_alone() -> None:
    # Taint path + location is a single independent source: impact layer is
    # reported but the verdict stays UNCERTAIN (impact alone never confirms).
    evidence = [
        make_evidence("e1", EvidenceType.TAINT_PATH, reliability=0.8),
    ]
    candidate = make_candidate(evidence_ids=["e1"])
    result = await _verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.UNCERTAIN
    assert result.metadata["stage"] == "under_proven"
    layers = _layers(result)
    assert layers[VerificationLayer.SECURITY_IMPACT_SUPPORTED.value] is True
    assert layers[VerificationLayer.ROOT_CAUSE_SUPPORTED.value] is False


async def test_root_cause_plus_impact_confirms_with_impact_note() -> None:
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, reliability=0.6),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, reliability=0.7),
        make_evidence("e3", EvidenceType.TAINT_PATH, reliability=0.8),
    ]
    candidate = make_candidate(evidence_ids=["e1", "e2", "e3"])
    result = await _verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    layers = _layers(result)
    assert layers[VerificationLayer.ROOT_CAUSE_SUPPORTED.value] is True
    assert layers[VerificationLayer.SECURITY_IMPACT_SUPPORTED.value] is True
    assert "Security-impact" in result.rationale


async def test_guard_memory_class_rejects_model_only_root_cause() -> None:
    evidence = [make_evidence("e1", EvidenceType.MODEL_REASONING_SUMMARY, reliability=0.9)]
    candidate = make_candidate(cwe_id="CWE-476", evidence_ids=["e1"])
    result = await _verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.REJECTED
    assert result.metadata["stage"] == "guard_model_reasoning"


async def test_guard_memory_class_allows_root_cause_confirmation() -> None:
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, reliability=0.6),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, reliability=0.7),
    ]
    candidate = make_candidate(cwe_id="CWE-476", evidence_ids=["e1", "e2"])
    result = await _verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    assert _layers(result)[VerificationLayer.ROOT_CAUSE_SUPPORTED.value] is True


async def test_auxiliary_alone_stays_uncertain_with_layer_breakdown() -> None:
    evidence = [
        make_evidence("e1", EvidenceType.FUZZ_INPUT, reliability=0.9),
        make_evidence("e2", EvidenceType.COVERAGE, reliability=0.9),
    ]
    candidate = make_candidate(evidence_ids=["e1", "e2"])
    result = await _verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.UNCERTAIN
    assert result.metadata["stage"] == "auxiliary_only"
    assert all(value is False for value in _layers(result).values())


async def test_verifier_never_mutates_candidate_or_raises() -> None:
    evidence = [make_evidence("e1", EvidenceType.CODE_SNIPPET, reliability=0.7)]
    candidate = make_candidate(evidence_ids=["e1"])
    await _verify(candidate, evidence)
    assert candidate.status is VulnerabilityStatus.CANDIDATE
    assert candidate.evidence_ids == ["e1"]
