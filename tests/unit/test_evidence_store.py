from vulnagent.core.models import Evidence, EvidenceType
from vulnagent.evidence.store import InMemoryEvidenceStore


def test_add_get_and_list_by_task() -> None:
    store = InMemoryEvidenceStore()
    item = Evidence(evidence_id="e1", task_id="t1", evidence_type=EvidenceType.TOOL_RESULT, source="mock", description="mock", reliability=0.5, created_by="test")
    store.add(item)
    assert store.get("e1") == item
    assert store.list_by_task("t1") == [item]
    assert store.list_by_task("other") == []

