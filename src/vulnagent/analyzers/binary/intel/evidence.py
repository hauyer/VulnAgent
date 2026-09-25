"""V0.7 Binary Intelligence: Binary Evidence Graph construction.

Turns the ``external input -> function -> dangerous callsite`` chains produced
by :class:`BinaryXrefAnalyzer` into a node/edge evidence graph plus a list of
evidence records, following the same {nodes, edges} shape used by the source
side ``build_evidence_graph`` so consumers can treat both uniformly.
"""

from __future__ import annotations

from typing import Any

from vulnagent.contracts import EvidenceV2, EvidenceType


def build_binary_evidence_graph(
    xref_result: dict[str, Any],
    *,
    task_id: str,
    target_id: str,
    session_id: str,
    run_id: str,
) -> tuple[list[EvidenceV2], dict[str, Any]]:
    """Return (evidence list, graph dict) for the xref chains."""
    evidence: list[EvidenceV2] = []
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_nodes: set[tuple[str, str]] = set()

    def add_node(kind: str, label: str, detail: dict[str, Any]) -> str:
        key = (kind, label)
        if key not in seen_nodes:
            seen_nodes.add(key)
            nodes.append({"id": f"{kind}:{label}", "kind": kind, "label": label, "detail": detail})
        return f"{kind}:{label}"

    for index, chain in enumerate(xref_result.get("chains", [])):
        input_id = add_node(
            "input",
            "/".join(chain.get("input_api", [])),
            {"source": chain.get("input_source")},
        )
        function_id = add_node(
            "function",
            chain.get("function_id", ""),
            {"start": chain.get("function_start")},
        )
        callsite_id = add_node(
            "callsite",
            f"{chain.get('dangerous_api')}@{chain.get('callsite_address'):x}"
            if isinstance(chain.get("callsite_address"), int)
            else str(chain.get("dangerous_api")),
            {"category": chain.get("dangerous_category"), "kind": chain.get("kind")},
        )
        edges.append({"source": input_id, "target": function_id, "label": "inputs_to"})
        edges.append({"source": function_id, "target": callsite_id, "label": "reaches"})

        evidence.append(
            EvidenceV2(
                evidence_id=f"{run_id}-ev-xref-{index}",
                task_id=task_id,
                session_id=session_id,
                evidence_type=EvidenceType.DISASSEMBLY,
                producer="pe-x64-iat-xref",
                analysis_run_id=run_id,
                derivation_id=f"{run_id}-chain-{index}",
                independence_group="binary-xref",
                reliability=0.7,
                description=(
                    f"external input ({chain.get('input_source')}) reaches dangerous "
                    f"{chain.get('dangerous_api')} in stripped function "
                    f"{chain.get('function_id')} at {chain.get('callsite_address'):x}"
                    if isinstance(chain.get("callsite_address"), int)
                    else f"external input reaches dangerous {chain.get('dangerous_api')}"
                ),
                data={
                    "target_id": target_id,
                    "chain": chain,
                    "graph_kind": "binary-evidence",
                },
            )
        )

    graph: dict[str, Any] = {
        "nodes": nodes,
        "edges": edges,
        "task_id": task_id,
        "target_id": target_id,
        "run_id": run_id,
        "engine": "binary-xref",
    }
    return evidence, graph
