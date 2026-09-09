from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityStatus,
)
from vulnagent.evidence.graph import build_evidence_graph
from vulnagent.evidence.store import InMemoryEvidenceStore


def _evidence(evidence_id: str, *, finding_id: str | None = None) -> Evidence:
    data = {"finding_id": finding_id} if finding_id else {}
    return Evidence(
        evidence_id=evidence_id,
        task_id="task-1",
        evidence_type=EvidenceType.TOOL_RESULT,
        source="fixture",
        description="A structured test result",
        reliability=0.9,
        created_by="test",
        data=data,
    )


def test_store_deduplicates_equivalent_evidence_and_indexes_findings() -> None:
    store = InMemoryEvidenceStore()
    original = _evidence("evidence-1", finding_id="finding-1")
    duplicate = _evidence("evidence-2", finding_id="finding-1")

    assert store.save(original) == original
    assert store.save(duplicate) == original
    assert store.list_by_task("task-1") == [original]
    assert store.list_by_finding("finding-1") == [original]


def test_evidence_graph_only_connects_public_contract_objects() -> None:
    finding = VulnerabilityCandidate(
        vulnerability_id="finding-1",
        task_id="task-1",
        title="Unsafe input",
        vulnerability_type="injection",
        description="Fixture finding",
        target_id="target-1",
        source_agent="audit",
        confidence=0.7,
        evidence_ids=["evidence-1"],
    )
    verification = VerificationResult(
        vulnerability_id="finding-1",
        task_id="task-1",
        status=VulnerabilityStatus.CONFIRMED,
        confidence=0.9,
        rationale="Reproduced from supplied evidence",
        evidence_ids=["evidence-1"],
    )

    graph = build_evidence_graph([finding], [_evidence("evidence-1")], [verification])

    assert {node["id"] for node in graph["nodes"]} == {
        "finding:finding-1",
        "verification:finding-1",
        "evidence:evidence-1",
    }
    assert {edge["kind"] for edge in graph["edges"]} == {"supported_by", "verified_by", "based_on"}
