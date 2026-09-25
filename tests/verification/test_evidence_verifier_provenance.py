"""V0.5 provenance-aware verifier scenarios.

The key regression the blueprint fixes: three probative evidence *types* split
out of ONE analysis family (same independence_group) must count as ONE
independent source and must NOT reach CONFIRMED.  Two genuinely independent
groups (e.g. native-taint + semgrep) still confirm.
"""

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


def make_candidate(
    evidence_ids: list[str] | None = None,
    *,
    location: VulnerabilityLocation | None = None,
) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id="v1",
        task_id=TASK_ID,
        title="Potential command injection",
        vulnerability_type="command_injection",
        description="User input may reach an unsafe sink.",
        target_id="target-1",
        location=location or VulnerabilityLocation(file_path="a.py", function_name="parse", line_start=1, line_end=2),
        source_agent="source_audit",
        source_type="source",
        confidence=0.6,
        severity="HIGH",
        evidence_ids=evidence_ids or [],
    )


def make_evidence(
    evidence_id: str,
    evidence_type: EvidenceType,
    *,
    group: str | None = None,
    reliability: float = 0.7,
) -> Evidence:
    data = {}
    if group is not None:
        data["provenance"] = {"independence_group": group}
    return Evidence(
        evidence_id=evidence_id,
        task_id=TASK_ID,
        evidence_type=evidence_type,
        source="producer-x",
        description=f"{evidence_type.value} evidence",
        reliability=reliability,
        created_by="producer-x",
        data=data,
    )


async def verify(candidate: VulnerabilityCandidate, evidence: list[Evidence]) -> VerificationResult:
    verifier = EvidenceVerifier()
    return await verifier.verify(candidate, VerificationContext(task_id=TASK_ID, evidence=evidence))


async def test_one_analysis_family_three_types_is_not_confirmed() -> None:
    # Core V0.5 regression: native-taint emits SOURCE_LOCATION + CODE_SNIPPET +
    # TAINT_PATH — all from ONE independence group.  Pre-V0.5 this was counted
    # as 3 probative kinds and wrongly CONFIRMED.
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, group="native-taint"),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, group="native-taint"),
        make_evidence("e3", EvidenceType.TAINT_PATH, group="native-taint"),
    ]
    candidate = make_candidate(["e1", "e2", "e3"])
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.UNCERTAIN
    assert result.metadata["stage"] == "under_proven"
    assert result.metadata["independent_count"] == 1
    assert result.metadata["independent_sources"] == ["native-taint"]


async def test_two_independent_groups_confirm() -> None:
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, group="native-taint"),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, group="semgrep"),
    ]
    candidate = make_candidate(["e1", "e2"])
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    assert result.metadata["stage"] == "static_corroboration"
    assert result.metadata["independent_count"] == 2
    assert result.metadata["independent_sources"] == ["native-taint", "semgrep"]


async def test_legacy_evidence_without_groups_keeps_old_behaviour() -> None:
    # No provenance anywhere: falls back to evidence types -> 2 sources -> confirm.
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION),
        make_evidence("e2", EvidenceType.CODE_SNIPPET),
    ]
    candidate = make_candidate(["e1", "e2"])
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    assert result.metadata["independent_count"] == 2


async def test_single_group_without_location_stays_uncertain() -> None:
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, group="native-taint"),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, group="native-taint"),
    ]
    candidate = make_candidate(["e1", "e2"], location=VulnerabilityLocation())
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.UNCERTAIN
    assert "lacks a usable location" in result.rationale


async def test_runtime_proof_records_independent_sources() -> None:
    evidence = [
        make_evidence("e1", EvidenceType.CRASH_LOG, group="asan", reliability=0.95),
        make_evidence("e2", EvidenceType.STACK_TRACE, group="asan", reliability=0.9),
    ]
    candidate = make_candidate(["e1", "e2"])
    result = await verify(candidate, evidence)
    assert result.status is VulnerabilityStatus.CONFIRMED
    assert result.metadata["stage"] == "runtime_proof"
    assert result.metadata["independent_sources"] == ["asan"]


async def test_same_group_does_not_inflate_confidence() -> None:
    # Confidence must reflect the single independent source, not 3 types.
    evidence = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, group="native-taint", reliability=0.8),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, group="native-taint", reliability=0.8),
        make_evidence("e3", EvidenceType.TAINT_PATH, group="native-taint", reliability=0.8),
    ]
    candidate = make_candidate(["e1", "e2", "e3"])
    result = await verify(candidate, evidence)
    # single-source confidence band stays below confirm-level confidence
    assert result.confidence < 0.7
