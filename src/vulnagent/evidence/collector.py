"""Evidence collection helper."""

from vulnagent.contracts import Evidence, EvidenceRepository


class EvidenceCollector:
    """Persist a batch of structured evidence."""

    def __init__(self, store: EvidenceRepository) -> None:
        self.store = store

    def collect(self, evidence: list[Evidence]) -> None:
        for item in evidence:
            self.store.save(item)
