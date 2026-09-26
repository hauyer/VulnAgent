"""WP6: triage of unknown-target candidates against historical knowledge.

A novel finding is never asserted by the engine: the triage classifies each
candidate as a known duplicate, an unverified novel candidate, or
insufficient evidence, and anything that survives goes to human review.
Negative observations are logged but, on the exploratory track with no
preset positive example, are never counted as true negatives.

S5 extension (roadmap work-package C step 4): post-freeze dedup classification
against public advisories/CVEs, using exactly the four classes the roadmap
defines -- novelty_unknown / known_duplicate / false_positive /
needs_more_evidence -- with reproducible evidence and independent verification
as inputs.
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


class DedupClass(str, Enum):
    """S5 post-freeze novelty classification (roadmap work-package C)."""

    NOVELTY_UNKNOWN = "novelty_unknown"
    KNOWN_DUPLICATE = "known_duplicate"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"


@dataclass(slots=True)
class PublicAdvisory:
    """A verified public record used for dedup (CVE / advisory)."""

    cve_id: str
    root_cause_fingerprint: str  # distinctive function/symbol/message text
    affected_version: str
    fixed_revision: str | None
    source: str  # e.g. "nvd", "cve.org", "redhat_bugzilla", "vulncheck"
    url: str = ""


@dataclass(slots=True)
class DedupResult:
    candidate_ref: str
    dedup_class: DedupClass
    matched: list[PublicAdvisory] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


class DedupClassifier:
    """Classify a frozen discovery record into the roadmap's four classes.

    Decision table (deterministic):
      * public advisory matches the root-cause fingerprint (and, where
        relevant, the affected version) -> ``KNOWN_DUPLICATE``.
      * not reproducible (replay fails) or verification rejected the fault ->
        ``FALSE_POSITIVE``.
      * reproducible fault with an independent verdict, but no public match
        and no human maintainer review yet -> ``NEEDS_MORE_EVIDENCE``
        (the engine never asserts novelty without human confirmation).
      * reproducible + verified + human review completed + no public match ->
        ``NOVELTY_UNKNOWN`` (a candidate to carry into disclosure discussion;
        still not an assertion of a 0-day).
    """

    def __init__(self, advisories: list[PublicAdvisory] | None = None) -> None:
        self.advisories: list[PublicAdvisory] = list(advisories or [])

    def register(self, advisory: PublicAdvisory) -> None:
        self.advisories.append(advisory)

    @staticmethod
    def _match(meta: dict[str, Any], adv: PublicAdvisory) -> bool:
        corpus = " ".join(
            str(meta.get(key, "")) for key in ("title", "description", "root_cause")
        ).lower()
        token = adv.root_cause_fingerprint.lower()
        return bool(re.search(rf"\b{re.escape(token)}\b", corpus))

    def classify(
        self,
        candidate_ref: str,
        meta: dict[str, Any],
        *,
        reproducible: bool,
        verification_status: str,
        human_reviewed: bool = False,
    ) -> DedupResult:
        reasons: list[str] = []
        matched: list[PublicAdvisory] = []

        for adv in self.advisories:
            if self._match(meta, adv):
                matched.append(adv)

        if matched:
            reasons.append(
                f"public {matched[0].source} record {matched[0].cve_id} matches "
                f"root-cause fingerprint '{matched[0].root_cause_fingerprint}' "
                f"(affected {matched[0].affected_version})"
            )
            return DedupResult(
                candidate_ref=candidate_ref,
                dedup_class=DedupClass.KNOWN_DUPLICATE,
                matched=matched,
                reasons=reasons,
            )

        if not reproducible:
            reasons.append("replay did not reproduce the fault; no verifiable finding")
            return DedupResult(
                candidate_ref=candidate_ref,
                dedup_class=DedupClass.FALSE_POSITIVE,
                reasons=reasons,
            )

        if verification_status not in {"CONFIRMED"}:
            reasons.append(
                f"independent verification did not confirm the fault "
                f"(status={verification_status})"
            )
            return DedupResult(
                candidate_ref=candidate_ref,
                dedup_class=DedupClass.FALSE_POSITIVE,
                reasons=reasons,
            )

        if not human_reviewed:
            reasons.append(
                "reproducible + independently confirmed fault, but no public match "
                "and no human maintainer review yet -> evidence insufficient to "
                "assert novelty"
            )
            return DedupResult(
                candidate_ref=candidate_ref,
                dedup_class=DedupClass.NEEDS_MORE_EVIDENCE,
                reasons=reasons,
            )

        reasons.append(
            "reproducible + independently confirmed + human-reviewed + no public "
            "match -> carries into disclosure discussion as a candidate of unknown "
            "novelty (not asserted as a 0-day)"
        )
        return DedupResult(
            candidate_ref=candidate_ref,
            dedup_class=DedupClass.NOVELTY_UNKNOWN,
            reasons=reasons,
        )
