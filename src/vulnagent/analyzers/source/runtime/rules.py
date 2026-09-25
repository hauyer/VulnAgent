"""V0.8 Dynamic Confirmation: runtime-oriented static prechecks.

Lightweight, self-authored AST rules that turn unvalidated numeric/string
input flowing into index expressions and division into source candidates
(CWE-193 off-by-one / CWE-129 unchecked index, CWE-369 divide-by-zero).
These candidates are the ``Source Candidate`` entry point of the V0.8
dynamic-confirmation pipeline; the runtime layer then confirms them with a
real crash.

The rules use a deliberately simple local assignment-chain taint model:
``input()``, ``sys.stdin.readline()`` and ``sys.argv`` are sources, direct
assignments propagate taint within a function, and guard contexts (assert /
if / while conditions) neutralize a finding.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

_TAINT_SOURCES = {
    "input",
    "builtins.input",
    "sys.stdin.readline",
    "sys.argv",
    "argv",
}

_GUARD_NODES = (ast.If, ast.While, ast.Assert, ast.IfExp)


@dataclass(frozen=True, slots=True)
class PrecheckFinding:
    """A static precheck hit that becomes a VulnerabilityCandidate."""

    cwe_id: str
    vulnerability_type: str
    title: str
    description: str
    line: int
    sink: str
    source_kinds: list[str]
    confidence: float = 0.6


def _call_chain_name(call: ast.Call) -> str | None:
    node: ast.AST = call.func
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    else:
        return None
    return ".".join(reversed(parts))


def _collect_taint_sources(function: ast.FunctionDef) -> set[str]:
    """Names that receive input directly or via a trivial assignment chain."""
    tainted: set[str] = set()

    def expr_tainted(node: ast.AST | None) -> bool:
        """True when an expression depends on a tainted name."""
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in tainted
        if isinstance(node, (ast.Call, ast.Attribute, ast.BinOp, ast.UnaryOp, ast.Subscript)):
            for child in ast.iter_child_nodes(node):
                if expr_tainted(child):
                    return True
        return False

    changed = True
    while changed:
        changed = False
        for node in ast.walk(function):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if isinstance(value, ast.Call):
                    call = _call_chain_name(value)
                    if call and (call in _TAINT_SOURCES or call.endswith(".readline")):
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for target in targets:
                            if isinstance(target, ast.Name) and target.id not in tainted:
                                tainted.add(target.id)
                                changed = True
                        continue
                if expr_tainted(value):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name) and target.id not in tainted:
                            tainted.add(target.id)
                            changed = True
    return tainted


def _parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def _guarded(node: ast.AST, parents: dict[int, ast.AST]) -> bool:
    """True when the node sits inside a guard condition (assert/if/while)."""
    current = node
    seen: set[int] = set()
    while True:
        parent = parents.get(id(current))
        if parent is None or id(parent) in seen:
            return False
        seen.add(id(parent))
        if isinstance(parent, _GUARD_NODES):
            return True
        current = parent


def check_divide_by_zero(function: ast.FunctionDef, tainted: set[str]) -> list[PrecheckFinding]:
    parents = _parent_map(function)
    findings: list[PrecheckFinding] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.BinOp):
            continue
        if not isinstance(node.op, (ast.Div, ast.FloorDiv)):
            continue
        right = node.right
        if isinstance(right, ast.Name) and right.id in tainted and not _guarded(node, parents):
            findings.append(
                PrecheckFinding(
                    cwe_id="CWE-369",
                    vulnerability_type="divide_by_zero",
                    title="Divide by zero from unvalidated input",
                    description=(
                        f"Unvalidated input `{right.id}` flows into a division on line "
                        f"{node.lineno} without a guard."
                    ),
                    line=node.lineno,
                    sink="div",
                    source_kinds=["numeric_input"],
                    confidence=0.7,
                )
            )
    return findings


def check_unchecked_index(function: ast.FunctionDef, tainted: set[str]) -> list[PrecheckFinding]:
    parents = _parent_map(function)
    findings: list[PrecheckFinding] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Subscript):
            continue
        value = node.value
        if isinstance(value, (ast.List, ast.Tuple)):
            bound = len(value.elts)
        elif isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)):
            bound = len(value.value)
        else:
            continue
        index = node.slice
        if isinstance(index, ast.Name) and index.id in tainted and not _guarded(node, parents):
            findings.append(
                PrecheckFinding(
                    cwe_id="CWE-193",
                    vulnerability_type="off_by_one",
                    title="Unchecked input index into fixed-size buffer",
                    description=(
                        f"Input-derived index `{index.id}` reaches a {bound}-element "
                        f"buffer subscript on line {node.lineno} without a bounds check."
                    ),
                    line=node.lineno,
                    sink="subscript",
                    source_kinds=["numeric_input"],
                    confidence=0.7,
                )
            )
    return findings
