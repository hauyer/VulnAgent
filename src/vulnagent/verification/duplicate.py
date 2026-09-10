"""Minimal deterministic finding deduplication."""

from vulnagent.contracts import VulnerabilityCandidate


def deduplicate(findings: list[VulnerabilityCandidate]) -> list[VulnerabilityCandidate]:
    seen: set[tuple[str, str, str]] = set()
    result: list[VulnerabilityCandidate] = []
    for finding in findings:
        key = (finding.target_id, finding.vulnerability_type, str(finding.location))
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
