"""Deterministic finding deduplication for the verification boundary."""

from vulnagent.contracts import VulnerabilityCandidate


def _dedup_key(finding: VulnerabilityCandidate) -> tuple[str, str, str]:
    """Stable identity: owning target, vulnerability kind and precise location."""
    return (finding.target_id, finding.vulnerability_type, str(finding.location))


def partition_duplicates(
    findings: list[VulnerabilityCandidate],
) -> tuple[list[VulnerabilityCandidate], list[VulnerabilityCandidate]]:
    """Split findings into ``(unique, duplicates)`` preserving first-occurrence order.

    The first candidate for a given identity is kept; any later candidate with the
    same target/type/location is reported as a duplicate so callers can account for
    it (e.g. record it in verification metadata) instead of silently dropping it.
    """
    seen: set[tuple[str, str, str]] = set()
    unique: list[VulnerabilityCandidate] = []
    duplicates: list[VulnerabilityCandidate] = []
    for finding in findings:
        key = _dedup_key(finding)
        if key in seen:
            duplicates.append(finding)
        else:
            seen.add(key)
            unique.append(finding)
    return unique, duplicates


def deduplicate(findings: list[VulnerabilityCandidate]) -> list[VulnerabilityCandidate]:
    """Return findings with duplicates removed (stable, first candidate wins)."""
    unique, _ = partition_duplicates(findings)
    return unique
