"""Evidence store."""

from vulnagent.core.models import Evidence
from vulnagent.storage.memory import InMemoryStorage


class InMemoryEvidenceStore:
    """Store evidence independently from findings."""

    def __init__(self, storage: InMemoryStorage[Evidence] | None = None) -> None:
        self._storage = storage or InMemoryStorage()

    def add(self, evidence: Evidence) -> Evidence:
        return self._storage.save(evidence.evidence_id, evidence)

    def get(self, evidence_id: str) -> Evidence | None:
        return self._storage.get(evidence_id)

    def list_by_task(self, task_id: str) -> list[Evidence]:
        return [item for item in self._storage.list_all() if item.task_id == task_id]

