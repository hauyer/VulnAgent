"""Unit tests for the V0.5 EvidenceV2 DTO and its legacy mapping."""

from vulnagent.contracts import Evidence, EvidenceType, EvidenceV2

TASK_ID = "task-1"


def make_v2(**overrides) -> EvidenceV2:
    defaults = dict(
        evidence_id="ev-1",
        task_id=TASK_ID,
        session_id="sess-1",
        evidence_type=EvidenceType.TAINT_PATH,
        producer="native-taint",
        producer_version="0.3.0",
        analysis_run_id="run-42",
        derivation_id="deriv-7",
        independence_group="native-taint",
        parent_evidence_ids=["ev-0"],
        subject_ids=["func:build_query"],
        reliability=0.8,
        artifact_refs=["art://cfgs/run-42.json"],
        description="taint path from request.args to os.system",
    )
    defaults.update(overrides)
    return EvidenceV2(**defaults)


def test_to_legacy_preserves_all_provenance_fields() -> None:
    legacy = make_v2().to_legacy()
    assert isinstance(legacy, Evidence)
    assert legacy.evidence_id == "ev-1"
    assert legacy.task_id == TASK_ID
    assert legacy.evidence_type is EvidenceType.TAINT_PATH
    assert legacy.reliability == 0.8
    assert legacy.source == "native-taint"
    assert legacy.created_by == "native-taint"
    provenance = legacy.data["provenance"]
    assert provenance["session_id"] == "sess-1"
    assert provenance["analysis_run_id"] == "run-42"
    assert provenance["derivation_id"] == "deriv-7"
    assert provenance["independence_group"] == "native-taint"
    assert provenance["parent_evidence_ids"] == ["ev-0"]
    assert provenance["subject_ids"] == ["func:build_query"]
    assert provenance["artifact_refs"] == ["art://cfgs/run-42.json"]


def test_from_evidence_round_trip_is_lossless() -> None:
    original = make_v2()
    rebuilt = EvidenceV2.from_evidence(original.to_legacy())
    assert rebuilt.evidence_id == original.evidence_id
    assert rebuilt.session_id == original.session_id
    assert rebuilt.evidence_type is original.evidence_type
    assert rebuilt.producer == original.producer
    assert rebuilt.producer_version == original.producer_version
    assert rebuilt.analysis_run_id == original.analysis_run_id
    assert rebuilt.derivation_id == original.derivation_id
    assert rebuilt.independence_group == original.independence_group
    assert rebuilt.parent_evidence_ids == original.parent_evidence_ids
    assert rebuilt.subject_ids == original.subject_ids
    assert rebuilt.artifact_refs == original.artifact_refs
    assert rebuilt.reliability == original.reliability
    assert rebuilt.description == original.description


def test_from_legacy_without_provenance_falls_back_gracefully() -> None:
    legacy = Evidence(
        evidence_id="ev-9",
        task_id=TASK_ID,
        evidence_type=EvidenceType.CODE_SNIPPET,
        source="old-auditor",
        description="snippet",
        reliability=0.6,
        created_by="old-auditor",
        data={"some": "payload"},
    )
    rebuilt = EvidenceV2.from_evidence(legacy)
    assert rebuilt.independence_group is None
    assert rebuilt.analysis_run_id is None
    assert rebuilt.producer == "old-auditor"
    assert rebuilt.data["some"] == "payload"


def test_minimal_v2_without_optional_provenance_fields() -> None:
    v2 = EvidenceV2(
        evidence_id="ev-2",
        task_id=TASK_ID,
        evidence_type=EvidenceType.SOURCE_LOCATION,
        producer="semgrep",
        reliability=0.6,
    )
    legacy = v2.to_legacy()
    provenance = legacy.data["provenance"]
    assert provenance["producer"] == "semgrep"
    assert "independence_group" not in provenance
