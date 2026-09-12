"""Internal normalized AST/CFG models for C, C++ and Go.

These models are deliberately internal to the source-parser boundary.  They
are serialized into ``SourceAnalysisResult.metadata`` so the audit layer can
consume deterministic facts without changing the frozen public contracts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class NormalizedAstNode:
    """One bounded, language-neutral syntax-tree node."""

    node_id: str
    node_type: str
    text: str
    line_start: int
    line_end: int
    column: int
    parent_id: str | None = None


@dataclass(frozen=True, slots=True)
class ControlFlowNode:
    """One statement or control decision in a normalized CFG."""

    node_id: str
    node_type: str
    text: str
    line: int


@dataclass(frozen=True, slots=True)
class ControlFlowEdge:
    """Directed CFG edge with an explainable branch kind."""

    source: str
    target: str
    kind: str = "next"


@dataclass(slots=True)
class NativeFunctionIR:
    """Normalized per-function representation consumed by static rules."""

    name: str
    qualified_name: str
    kind: str
    line_start: int
    line_end: int
    column: int
    parameters: list[dict[str, Any]] = field(default_factory=list)
    cfg_nodes: list[ControlFlowNode] = field(default_factory=list)
    cfg_edges: list[ControlFlowEdge] = field(default_factory=list)
    facts: list[dict[str, Any]] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "qualified_name": self.qualified_name,
            "kind": self.kind,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "column": self.column,
            "parameters": list(self.parameters),
            "cfg": {
                "nodes": [asdict(item) for item in self.cfg_nodes],
                "edges": [asdict(item) for item in self.cfg_edges],
            },
            "facts": list(self.facts),
            "callees": list(self.callees),
        }


@dataclass(slots=True)
class NativeFileAnalysis:
    """Complete read-only parse result for one C/C++/Go source file."""

    file_path: str
    language: str
    ast_nodes: list[NormalizedAstNode] = field(default_factory=list)
    functions: list[NativeFunctionIR] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    has_syntax_error: bool = False
    ast_truncated: bool = False

    def to_metadata(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "ast": {
                "nodes": [asdict(item) for item in self.ast_nodes],
                "truncated": self.ast_truncated,
            },
            "functions": [item.to_metadata() for item in self.functions],
            "dependencies": list(self.dependencies),
            "has_syntax_error": self.has_syntax_error,
        }


__all__ = [
    "ControlFlowEdge",
    "ControlFlowNode",
    "NativeFileAnalysis",
    "NativeFunctionIR",
    "NormalizedAstNode",
]
