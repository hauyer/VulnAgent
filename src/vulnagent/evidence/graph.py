"""Build a small, serialisable evidence graph from public contracts only."""

from __future__ import annotations

from typing import Any

from vulnagent.contracts import Evidence, VerificationResult, VulnerabilityCandidate


def build_evidence_graph(
    findings: list[VulnerabilityCandidate],
    evidence: list[Evidence],
    verifications: list[VerificationResult],
) -> dict[str, list[dict[str, Any]]]:
    """Create display-ready nodes and edges without interpreting analyzer objects."""
    evidence_by_id = {item.evidence_id: item for item in evidence}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []

    for finding in findings:
        finding_node = f"finding:{finding.vulnerability_id}"
        nodes.append({"id": finding_node, "kind": "finding", "label": finding.title})
        for evidence_id in finding.evidence_ids:
            _append_evidence_edge(nodes, edges, evidence_by_id, finding_node, evidence_id, "supported_by")

    for verification in verifications:
        verification_node = f"verification:{verification.vulnerability_id}"
        nodes.append({"id": verification_node, "kind": "verification", "label": verification.status.value})
        edges.append({"from": f"finding:{verification.vulnerability_id}", "to": verification_node, "kind": "verified_by"})
        for evidence_id in verification.evidence_ids:
            _append_evidence_edge(nodes, edges, evidence_by_id, verification_node, evidence_id, "based_on")

    return {"nodes": nodes, "edges": edges}


def _append_evidence_edge(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, str]],
    evidence_by_id: dict[str, Evidence],
    parent: str,
    evidence_id: str,
    relation: str,
) -> None:
    evidence = evidence_by_id.get(evidence_id)
    if evidence is None:
        return
    node_id = f"evidence:{evidence_id}"
    if not any(node["id"] == node_id for node in nodes):
        nodes.append({"id": node_id, "kind": "evidence", "label": evidence.evidence_type.value, "source": evidence.source})
    edges.append({"from": parent, "to": node_id, "kind": relation})
