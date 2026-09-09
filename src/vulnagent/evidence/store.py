"""In-memory evidence persistence with deterministic de-duplication."""

from __future__ import annotations

import hashlib
import json

from vulnagent.contracts import Evidence
from vulnagent.storage.memory import InMemoryStorage


class InMemoryEvidenceStore:
    """Store evidence independently from findings."""

    def __init__(self, storage: InMemoryStorage[Evidence] | None = None) -> None:
        self._storage = storage or InMemoryStorage()
        self._fingerprints: dict[str, str] = {}

    def add(self, evidence: Evidence) -> Evidence:
        return self.save(evidence)

    def save(self, evidence: Evidence) -> Evidence:
        """Persist evidence, returning an existing semantic duplicate when present.

        Evidence producers create IDs independently.  A stable fingerprint prevents
        an identical tool result from becoming several misleadingly independent
        pieces of evidence while leaving evidence with different provenance intact.
        """
        fingerprint = self._fingerprint(evidence)
        existing_id = self._fingerprints.get(fingerprint)
        if existing_id is not None:
            existing = self._storage.get(existing_id)
            if existing is not None:
                return existing
        for known_fingerprint, known_id in list(self._fingerprints.items()):
            if known_id == evidence.evidence_id:
                del self._fingerprints[known_fingerprint]
        self._fingerprints[fingerprint] = evidence.evidence_id
        return self._storage.save(evidence.evidence_id, evidence)

    def _fingerprint(self, evidence: Evidence) -> str:
        payload = evidence.model_dump(mode="json", exclude={"evidence_id", "created_at"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        fingerprint = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        return fingerprint

    def get(self, evidence_id: str) -> Evidence | None:
        return self._storage.get(evidence_id)

    def list_by_task(self, task_id: str) -> list[Evidence]:
        return [item for item in self._storage.list_all() if item.task_id == task_id]

    def list_by_finding(self, finding_id: str) -> list[Evidence]:
        """Return evidence explicitly associated through public evidence metadata.

        Producers may use either ``finding_id`` or ``finding_ids`` in ``data``.
        This convention avoids adding a P9-specific field to the frozen Evidence
        contract while supporting one-to-many evidence chains.
        """
        return [
            item
            for item in self._storage.list_all()
            if item.data.get("finding_id") == finding_id
            or finding_id in item.data.get("finding_ids", [])
        ]
