"""Evidence independence evaluation (V0.5 Evidence Provenance).

The verifier must not treat three evidence pieces from the *same* analysis
family (e.g. native-taint emitting SOURCE_LOCATION + CODE_SNIPPET + TAINT_PATH)
as three independent sources.  This module resolves the independence group of
any evidence and counts distinct groups.

Backwards compatibility: legacy evidence without provenance metadata falls back
to its evidence type, which reproduces the pre-V0.5 behaviour exactly.
"""
from typing import Any

from vulnagent.contracts import Evidence

PROVENANCE_KEY = "provenance"


def provenance_of(evidence: Evidence) -> dict[str, Any]:
    """Return the provenance dict carried on a legacy Evidence (may be empty)."""
    data = evidence.data or {}
    provenance = data.get(PROVENANCE_KEY)
    if isinstance(provenance, dict):
        return provenance
    return {}


def independence_group_of(evidence: Evidence) -> str:
    """Resolve the independence group of an evidence item.

    Resolution order:
      1. ``data["provenance"]["independence_group"]`` (new V2 format)
      2. ``data["independence_group"]`` (direct key convenience)
      3. fallback: the evidence type — legacy behaviour.
    """
    provenance = provenance_of(evidence)
    group = provenance.get("independence_group")
    if group:
        return str(group)
    direct = (evidence.data or {}).get("independence_group")
    if direct:
        return str(direct)
    return evidence.evidence_type.value


class EvidenceIndependenceEvaluator:
    """Counts distinct independent sources among a set of evidence items."""

    def independent_sources(self, items: list[Evidence]) -> list[str]:
        """Return the ordered list of distinct independence groups."""
        seen: dict[str, bool] = {}
        ordered: list[str] = []
        for item in items:
            group = independence_group_of(item)
            if group not in seen:
                seen[group] = True
                ordered.append(group)
        return ordered

    def count(self, items: list[Evidence]) -> int:
        """Number of distinct independent sources (fallback: distinct types)."""
        return len(self.independent_sources(items))


__all__ = [
    "EvidenceIndependenceEvaluator",
    "independence_group_of",
    "provenance_of",
]
