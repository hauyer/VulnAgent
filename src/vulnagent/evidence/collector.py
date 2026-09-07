"""Evidence collection helper."""

from vulnagent.core.models import Evidence
from vulnagent.evidence.store import InMemoryEvidenceStore


class EvidenceCollector:
    """Persist a batch of structured evidence."""

    def __init__(self, store: InMemoryEvidenceStore) -> None:
        self.store = store

    def collect(self, evidence: list[Evidence]) -> None:
        for item in evidence:
            self.store.add(item)

