"""Unit tests for P7 single-source candidate canonicalization."""

from vulnagent.agents.verification_agent import canonicalize_candidates
from vulnagent.contracts import VulnerabilityCandidate, VulnerabilityLocation


def make_candidate(
    vulnerability_id: str,
    *,
    location: VulnerabilityLocation | None = None,
    evidence_ids: list[str] | None = None,
    vulnerability_type: str = "command_injection",
) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id=vulnerability_id,
        task_id="task-1",
        title="Potential command injection",
        vulnerability_type=vulnerability_type,
        description="User input may reach an unsafe sink.",
        target_id="target-1",
        location=location,
        source_agent="source_audit",
        source_type="source",
        confidence=0.6,
        severity="HIGH",
        evidence_ids=evidence_ids or [],
    )


def reliable_loc(file_path: str = "a.c") -> VulnerabilityLocation:
    return VulnerabilityLocation(file_path=file_path, function_name="parse", line_start=1, line_end=2)


def test_exact_duplicates_merge_into_canonical_with_fused_evidence() -> None:
    a = make_candidate("v1", location=reliable_loc(), evidence_ids=["e1"])
    b = make_candidate("v2", location=reliable_loc(), evidence_ids=["e2"])
    result, merged = canonicalize_candidates([a, b])

    assert merged == 1
    assert [item.vulnerability_id for item in result] == ["v1"]
    canonical = result[0]
    assert canonical.evidence_ids == ["e1", "e2"]  # evidence fused
    assert canonical.metadata["duplicate_ids"] == ["v2"]  # traceable


def test_three_duplicates_fuse_and_trace_all_ids() -> None:
    a = make_candidate("v1", location=reliable_loc(), evidence_ids=["e1"])
    b = make_candidate("v2", location=reliable_loc(), evidence_ids=["e2"])
    c = make_candidate("v3", location=reliable_loc(), evidence_ids=["e3"])
    result, merged = canonicalize_candidates([a, b, c])

    assert merged == 2
    assert len(result) == 1
    assert result[0].evidence_ids == ["e1", "e2", "e3"]
    assert result[0].metadata["duplicate_ids"] == ["v2", "v3"]


def test_none_location_candidates_are_never_merged() -> None:
    a = make_candidate("v1", location=None)
    b = make_candidate("v2", location=None)  # same type/target, but no location
    result, merged = canonicalize_candidates([a, b])

    assert merged == 0
    assert {item.vulnerability_id for item in result} == {"v1", "v2"}


def test_location_without_locator_is_not_merge_reliable() -> None:
    # function_name only is not a reliable locator -> do not collapse.
    weak = VulnerabilityLocation(function_name="parse")
    a = make_candidate("v1", location=weak)
    b = make_candidate("v2", location=weak)
    result, merged = canonicalize_candidates([a, b])

    assert merged == 0
    assert len(result) == 2


def test_distinct_locations_are_not_merged() -> None:
    a = make_candidate("v1", location=reliable_loc("a.c"))
    b = make_candidate("v2", location=reliable_loc("b.c"))
    result, merged = canonicalize_candidates([a, b])

    assert merged == 0
    assert len(result) == 2


def test_distinct_vulnerability_types_are_not_merged() -> None:
    a = make_candidate("v1", vulnerability_type="command_injection", location=reliable_loc())
    b = make_candidate("v2", vulnerability_type="sql_injection", location=reliable_loc())
    result, merged = canonicalize_candidates([a, b])

    assert merged == 0
    assert len(result) == 2


def test_same_id_reported_twice_counts_but_stays_single() -> None:
    a = make_candidate("v1", location=reliable_loc(), evidence_ids=["e1"])
    duplicate = make_candidate("v1", location=reliable_loc(), evidence_ids=["e1"])
    result, merged = canonicalize_candidates([a, duplicate])

    assert merged == 1
    assert len(result) == 1
    assert "duplicate_ids" not in result[0].metadata  # same id, no cross-id merge recorded
