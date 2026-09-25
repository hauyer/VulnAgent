"""WP6: triage of unknown-target candidates against historical knowledge.

A novel finding is never asserted by the engine: the triage classifies each
candidate as a known duplicate, an unverified novel candidate, or
insufficient evidence, and anything that survives goes to human review.
Negative observations are logged but, on the exploratory track with no
preset positive example, are never counted as true negatives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TriageDecision(str, Enum):
    DUPLICATE_KNOWN = "duplicate_known"
    KEEP_UNVERIFIED = "keep_unverified"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


@dataclass(slots=True)
class KnowledgeRecord:
    """A known-issue fact from upstream advisories / CVEfixes / CWE knowledge."""

    cwe_id: str
    fingerprint: str  # distinctive feature: symbol / call / message pattern
    source: str  # "cvefixes" | "upstream_advisory" | "cwe-knowledge"
    published: bool


@dataclass(slots=True)
class TriageResult:
    candidate_ref: str
    cwe_id: str
    decision: TriageDecision
    matched_known: list[KnowledgeRecord] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HistoricalKnowledgeDedup:
    """Match candidates against the historical knowledge table."""

    knowledge: list[KnowledgeRecord] = field(default_factory=list)

    def register(self, record: KnowledgeRecord) -> None:
        self.knowledge.append(record)

    @staticmethod
    def _fingerprint_hit(candidate: dict[str, Any], record: KnowledgeRecord) -> bool:
        corpus = " ".join(
            str(candidate.get(key, ""))
            for key in ("title", "description", "location", "note")
        ).lower()
        token = record.fingerprint.lower()
        if token in corpus:
            return True
        # Symbol-ish fingerprints also match on the location basename.
        if token in str(candidate.get("location", "")).lower():
            return True
        return bool(re.search(rf"\b{re.escape(token)}\b", corpus))

    def triage(self, candidate: dict[str, Any]) -> TriageResult:
        ref = str(candidate.get("candidate_id", ""))
        cwe = str(candidate.get("cwe_id", ""))
        evidence_count = int(candidate.get("evidence_count", 0))

        reasons: list[str] = []
        matched: list[KnowledgeRecord] = []

        for record in self.knowledge:
            if cwe and record.cwe_id and record.cwe_id.lower() != cwe.lower():
                continue
            if self._fingerprint_hit(candidate, record):
                matched.append(record)

        if matched:
            reasons.append(
                f"matches known issue from {matched[0].source} "
                f"(fingerprint={matched[0].fingerprint})"
            )
            return TriageResult(
                candidate_ref=ref,
                cwe_id=cwe,
                decision=TriageDecision.DUPLICATE_KNOWN,
                matched_known=matched,
                reasons=reasons,
            )

        if evidence_count == 0:
            reasons.append("no evidence attached; cannot assert a finding")
            return TriageResult(
                candidate_ref=ref,
                cwe_id=cwe,
                decision=TriageDecision.INSUFFICIENT_EVIDENCE,
                reasons=reasons,
            )

        reasons.append(
            "no match in historical knowledge; unverified novel candidate -- "
            "engine does not assert novelty; human review required"
        )
        return TriageResult(
            candidate_ref=ref,
            cwe_id=cwe,
            decision=TriageDecision.NEEDS_HUMAN_REVIEW,
            reasons=reasons,
        )

    @staticmethod
    def negative_note(target_id: str, detail: str) -> dict[str, str]:
        """Record a negative observation without counting it as a true negative."""
        return {
            "target_id": target_id,
            "kind": "negative",
            "detail": detail,
            "counted_as_tn": "false",
            "reason": "exploratory track: no preset positive example",
        }
