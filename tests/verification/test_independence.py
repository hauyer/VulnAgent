"""Unit tests for the V0.5 evidence independence evaluator."""

from vulnagent.contracts import Evidence, EvidenceType
from vulnagent.verification.independence import (
    EvidenceIndependenceEvaluator,
    independence_group_of,
    provenance_of,
)

TASK_ID = "task-1"


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


def test_legacy_evidence_without_provenance_falls_back_to_type() -> None:
    evidence = make_evidence("e1", EvidenceType.SOURCE_LOCATION)
    assert provenance_of(evidence) == {}
    assert independence_group_of(evidence) == "source_location"


def test_provenance_group_is_preferred() -> None:
    evidence = make_evidence("e1", EvidenceType.SOURCE_LOCATION, group="native-taint")
    assert independence_group_of(evidence) == "native-taint"


def test_direct_data_key_group_is_supported() -> None:
    evidence = Evidence(
        evidence_id="e1",
        task_id=TASK_ID,
        evidence_type=EvidenceType.CODE_SNIPPET,
        source="p",
        description="d",
        reliability=0.7,
        created_by="p",
        data={"independence_group": "semgrep"},
    )
    assert independence_group_of(evidence) == "semgrep"


def test_same_group_multiple_types_count_as_one_source() -> None:
    evaluator = EvidenceIndependenceEvaluator()
    items = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, group="native-taint"),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, group="native-taint"),
        make_evidence("e3", EvidenceType.TAINT_PATH, group="native-taint"),
    ]
    assert evaluator.count(items) == 1
    assert evaluator.independent_sources(items) == ["native-taint"]


def test_distinct_groups_count_separately() -> None:
    evaluator = EvidenceIndependenceEvaluator()
    items = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, group="native-taint"),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, group="semgrep"),
        make_evidence("e3", EvidenceType.DATA_FLOW, group="joern"),
    ]
    assert evaluator.count(items) == 3


def test_mixed_legacy_and_provenanced_evidence() -> None:
    evaluator = EvidenceIndependenceEvaluator()
    items = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, group="native-taint"),
        # Legacy piece (no group) falls back to its type as its own source.
        make_evidence("e2", EvidenceType.CODE_SNIPPET),
    ]
    assert evaluator.count(items) == 2
    assert evaluator.independent_sources(items) == ["native-taint", "code_snippet"]


def test_duplicate_groups_preserve_first_seen_order() -> None:
    evaluator = EvidenceIndependenceEvaluator()
    items = [
        make_evidence("e1", EvidenceType.SOURCE_LOCATION, group="semgrep"),
        make_evidence("e2", EvidenceType.CODE_SNIPPET, group="native-taint"),
        make_evidence("e3", EvidenceType.DATA_FLOW, group="semgrep"),
    ]
    assert evaluator.independent_sources(items) == ["semgrep", "native-taint"]


def test_empty_list_counts_zero() -> None:
    evaluator = EvidenceIndependenceEvaluator()
    assert evaluator.count([]) == 0
    assert evaluator.independent_sources([]) == []
