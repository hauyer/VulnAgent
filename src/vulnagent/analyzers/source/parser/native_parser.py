"""Offline Tree-sitter parser and normalized AST/CFG extractor.

Only local source bytes are read.  The parser does not invoke a compiler,
execute project code, resolve remote modules, or perform vulnerability
judgement.  C, C++ and Go grammars are installed as local Python wheels so
runtime parsing never downloads a grammar.
"""

from __future__ import annotations

import importlib
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from tree_sitter import Language, Node, Parser

from .native_models import (
    ControlFlowEdge,
    ControlFlowNode,
    NativeFileAnalysis,
    NativeFunctionIR,
    NormalizedAstNode,
)

_GRAMMAR_MODULES = {
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "go": "tree_sitter_go",
}
_FUNCTION_TYPES = {
    "c": frozenset({"function_definition"}),
    "cpp": frozenset({"function_definition"}),
    "go": frozenset({"function_declaration", "method_declaration"}),
}
_CONDITION_TYPES = frozenset(
    {"if_statement", "while_statement", "for_statement", "switch_statement"}
)
_LOOP_TYPES = frozenset({"while_statement", "for_statement", "range_clause"})
_ASSIGNMENT_TYPES = frozenset(
    {
        "assignment_expression",
        "init_declarator",
        "short_var_declaration",
        "assignment_statement",
        "var_spec",
    }
)
_INDEX_TYPES = frozenset({"subscript_expression", "index_expression"})
_IDENTIFIER_TYPES = frozenset(
    {"identifier", "field_identifier", "package_identifier", "type_identifier"}
)
_MAX_AST_NODES = 6_000
_MAX_NODE_TEXT = 240


class NativeSourceParseError(RuntimeError):
    """Raised when a configured local grammar cannot parse a source file."""


@lru_cache(maxsize=len(_GRAMMAR_MODULES))
def _parser_for(language: str) -> Parser:
    module_name = _GRAMMAR_MODULES.get(language)
    if module_name is None:
        raise NativeSourceParseError(f"unsupported native language: {language}")
    try:
        grammar = importlib.import_module(module_name)
        return Parser(Language(grammar.language()))
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        raise NativeSourceParseError(
            f"local Tree-sitter grammar unavailable for {language}"
        ) from exc


def _text(node: Node | None, source: bytes, *, limit: int = _MAX_NODE_TEXT) -> str:
    if node is None:
        return ""
    value = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    compact = " ".join(value.split())
    return compact[:limit]


def _walk(node: Node) -> Iterable[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _first_descendant(node: Node | None, types: set[str] | frozenset[str]) -> Node | None:
    if node is None:
        return None
    return next((item for item in _walk(node) if item.type in types), None)


def _identifier_names(node: Node | None, source: bytes) -> list[str]:
    if node is None:
        return []
    names: list[str] = []
    for item in _walk(node):
        if item.type not in _IDENTIFIER_TYPES:
            continue
        value = _text(item, source, limit=120)
        if value and value not in names:
            names.append(value)
    return names


def _declarator_name(node: Node | None, source: bytes) -> str:
    if node is None:
        return "<anonymous>"
    candidate = _first_descendant(
        node,
        frozenset({"identifier", "field_identifier", "qualified_identifier"}),
    )
    return _text(candidate, source, limit=160) or "<anonymous>"


def _module_name(displayed_path: str) -> str:
    return Path(displayed_path).with_suffix("").as_posix().replace("/", ".")


class _CfgBuilder:
    """Build a compact statement-level CFG for one function body."""

    def __init__(self, function_name: str, source: bytes) -> None:
        self.function_name = function_name
        self.source = source
        self.nodes: list[ControlFlowNode] = []
        self.edges: list[ControlFlowEdge] = []
        self._counter = 0
        self._return_nodes: list[str] = []

    def build(self, function: Node, body: Node) -> tuple[list[ControlFlowNode], list[ControlFlowEdge]]:
        entry = self._add("entry", function, self.function_name)
        exits = self._sequence(self._statements(body), [entry])
        exit_node = self._add("exit", function, self.function_name)
        for item in exits:
            self._edge(item, exit_node)
        for item in self._return_nodes:
            self._edge(item, exit_node, "return")
        return self.nodes, self.edges

    def _add(self, kind: str, node: Node, text: str | None = None) -> str:
        self._counter += 1
        node_id = f"cfg-{self._counter}"
        self.nodes.append(
            ControlFlowNode(
                node_id=node_id,
                node_type=kind,
                text=(text if text is not None else _text(node, self.source)),
                line=node.start_point.row + 1,
            )
        )
        return node_id

    def _edge(self, source: str, target: str, kind: str = "next") -> None:
        edge = ControlFlowEdge(source=source, target=target, kind=kind)
        if edge not in self.edges:
            self.edges.append(edge)

    @staticmethod
    def _statements(node: Node | None) -> list[Node]:
        if node is None:
            return []
        if node.type == "block" and len(node.named_children) == 1:
            only = node.named_children[0]
            if only.type == "statement_list":
                return list(only.named_children)
        if node.type in {"compound_statement", "statement_list", "block"}:
            return list(node.named_children)
        return [node]

    def _sequence(self, statements: list[Node], incoming: list[str]) -> list[str]:
        exits = list(incoming)
        for statement in statements:
            exits = self._statement(statement, exits)
            if not exits:
                break
        return exits

    def _statement(self, statement: Node, incoming: list[str]) -> list[str]:
        if statement.type == "if_statement":
            condition = statement.child_by_field_name("condition") or statement
            decision = self._add("condition", condition)
            for item in incoming:
                self._edge(item, decision)
            consequence = statement.child_by_field_name("consequence")
            alternative = statement.child_by_field_name("alternative")
            true_start = len(self.nodes)
            true_exits = self._sequence(self._statements(consequence), [decision])
            if len(self.nodes) > true_start:
                self._replace_edge_kind(decision, self.nodes[true_start].node_id, "true")
            false_start = len(self.nodes)
            false_exits = self._sequence(self._statements(alternative), [decision])
            if len(self.nodes) > false_start:
                self._replace_edge_kind(decision, self.nodes[false_start].node_id, "false")
            join = self._add("join", statement, "if-join")
            if consequence is None:
                true_exits = [decision]
            if alternative is None:
                false_exits = [decision]
            for item in [*true_exits, *false_exits]:
                self._edge(item, join, "false" if item == decision else "next")
            return [join]

        if statement.type in _LOOP_TYPES:
            condition = statement.child_by_field_name("condition") or statement
            decision = self._add("loop_condition", condition)
            for item in incoming:
                self._edge(item, decision)
            body = statement.child_by_field_name("body")
            body_start = len(self.nodes)
            body_exits = self._sequence(self._statements(body), [decision])
            if len(self.nodes) > body_start:
                self._replace_edge_kind(decision, self.nodes[body_start].node_id, "true")
            for item in body_exits:
                self._edge(item, decision, "back")
            join = self._add("join", statement, "loop-exit")
            self._edge(decision, join, "false")
            return [join]

        if statement.type in {"compound_statement", "statement_list", "block"}:
            return self._sequence(self._statements(statement), incoming)

        current = self._add(statement.type, statement)
        for item in incoming:
            self._edge(item, current)
        if statement.type == "return_statement":
            self._return_nodes.append(current)
            return []
        return [current]

    def _replace_edge_kind(self, source: str, target: str, kind: str) -> None:
        self.edges = [
            ControlFlowEdge(source=item.source, target=item.target, kind=kind)
            if item.source == source and item.target == target
            else item
            for item in self.edges
        ]


class NativeSourceParser:
    """Parse one C/C++/Go file into bounded normalized AST, CFG and facts."""

    supported_languages = frozenset(_GRAMMAR_MODULES)

    def parse_file(
        self,
        path: Path,
        displayed_path: str,
        language: str,
    ) -> NativeFileAnalysis:
        """Read and parse a local inventory file without executing it."""

        if language not in self.supported_languages:
            raise NativeSourceParseError(f"unsupported native language: {language}")
        try:
            source = path.read_bytes()
            tree = _parser_for(language).parse(source)
        except OSError as exc:
            raise NativeSourceParseError(f"unable to read {displayed_path}") from exc
        if tree is None:
            raise NativeSourceParseError(f"parser returned no tree for {displayed_path}")

        ast_nodes, truncated = self._ast(tree.root_node, source)
        functions = [
            self._function(item, source, displayed_path, language)
            for item in _walk(tree.root_node)
            if item.type in _FUNCTION_TYPES[language]
        ]
        functions.sort(key=lambda item: (item.line_start, item.qualified_name))
        return NativeFileAnalysis(
            file_path=displayed_path,
            language=language,
            ast_nodes=ast_nodes,
            functions=functions,
            dependencies=self._dependencies(tree.root_node, source, language),
            has_syntax_error=bool(tree.root_node.has_error),
            ast_truncated=truncated,
        )

    @staticmethod
    def _ast(root: Node, source: bytes) -> tuple[list[NormalizedAstNode], bool]:
        records: list[NormalizedAstNode] = []
        stack: list[tuple[Node, str | None]] = [(root, None)]
        while stack and len(records) < _MAX_AST_NODES:
            node, parent_id = stack.pop()
            node_id = f"ast-{len(records) + 1}"
            records.append(
                NormalizedAstNode(
                    node_id=node_id,
                    node_type=node.type,
                    text=_text(node, source),
                    line_start=node.start_point.row + 1,
                    line_end=node.end_point.row + 1,
                    column=node.start_point.column,
                    parent_id=parent_id,
                )
            )
            stack.extend((child, node_id) for child in reversed(node.named_children))
        return records, bool(stack)

    def _function(
        self,
        node: Node,
        source: bytes,
        displayed_path: str,
        language: str,
    ) -> NativeFunctionIR:
        if language == "go":
            name = _text(node.child_by_field_name("name"), source, limit=160)
        else:
            name = _declarator_name(node.child_by_field_name("declarator"), source)
        name = name or "<anonymous>"
        qualified_name = f"{_module_name(displayed_path)}.{name}"
        body = node.child_by_field_name("body")
        parameters = self._parameters(node, source, language)
        facts = self._facts(body, source, qualified_name, language)
        cfg_nodes: list[ControlFlowNode] = []
        cfg_edges: list[ControlFlowEdge] = []
        if body is not None:
            cfg_nodes, cfg_edges = _CfgBuilder(qualified_name, source).build(node, body)
        callees = list(
            dict.fromkeys(
                str(item["callee"])
                for item in facts
                if item.get("kind") == "call" and item.get("callee")
            )
        )
        return NativeFunctionIR(
            name=name,
            qualified_name=qualified_name,
            kind="method" if node.type == "method_declaration" else "function",
            line_start=node.start_point.row + 1,
            line_end=node.end_point.row + 1,
            column=node.start_point.column,
            parameters=parameters,
            cfg_nodes=cfg_nodes,
            cfg_edges=cfg_edges,
            facts=facts,
            callees=callees,
        )

    @staticmethod
    def _parameters(node: Node, source: bytes, language: str) -> list[dict[str, Any]]:
        parameters = node.child_by_field_name("parameters")
        if parameters is None:
            declarator = node.child_by_field_name("declarator")
            parameters = _first_descendant(declarator, frozenset({"parameter_list"}))
        output: list[dict[str, Any]] = []
        if parameters is None:
            return output
        for item in parameters.named_children:
            if "parameter" not in item.type:
                continue
            name_node = item.child_by_field_name("name")
            declarator = item.child_by_field_name("declarator")
            name = _text(name_node, source, limit=120) or _declarator_name(declarator, source)
            if not name or name == "<anonymous>":
                identifiers = _identifier_names(item, source)
                name = identifiers[0] if identifiers else "<anonymous>"
            type_node = item.child_by_field_name("type")
            output.append(
                {
                    "name": name,
                    "type": _text(type_node, source, limit=160),
                    "line": item.start_point.row + 1,
                    "source_kind": "api_parameter",
                    "language": language,
                }
            )
        return output

    def _facts(
        self,
        body: Node | None,
        source: bytes,
        function_name: str,
        language: str,
    ) -> list[dict[str, Any]]:
        if body is None:
            return []
        facts: list[dict[str, Any]] = []
        for node in _walk(body):
            base = {
                "line": node.start_point.row + 1,
                "end_line": node.end_point.row + 1,
                "column": node.start_point.column,
                "function": function_name,
                "language": language,
            }
            if node.type == "call_expression":
                function = node.child_by_field_name("function")
                arguments = node.child_by_field_name("arguments")
                argument_nodes = list(arguments.named_children) if arguments is not None else []
                facts.append(
                    {
                        **base,
                        "kind": "call",
                        "callee": _text(function, source, limit=180),
                        "arguments": [_text(item, source) for item in argument_nodes],
                        "argument_identifiers": [
                            _identifier_names(item, source) for item in argument_nodes
                        ],
                        "assigned_to": self._assigned_targets(node, source, body),
                        "text": _text(node, source),
                    }
                )
            elif node.type in _ASSIGNMENT_TYPES:
                assignment = self._assignment(node, source)
                if assignment is not None:
                    facts.append({**base, "kind": "assignment", **assignment})
            elif node.type in _CONDITION_TYPES:
                condition = node.child_by_field_name("condition")
                if condition is not None:
                    facts.append(
                        {
                            **base,
                            "kind": "condition",
                            "expression": _text(condition, source),
                            "identifiers": _identifier_names(condition, source),
                        }
                    )
            elif node.type in _INDEX_TYPES:
                container = (
                    node.child_by_field_name("argument")
                    or node.child_by_field_name("operand")
                )
                index = node.child_by_field_name("index")
                facts.append(
                    {
                        **base,
                        "kind": "index",
                        "container": _text(container, source),
                        "index": _text(index, source),
                        "index_identifiers": _identifier_names(index, source),
                        "text": _text(node, source),
                    }
                )
            elif node.type in {"pointer_expression", "unary_expression", "field_expression"}:
                expression = _text(node, source)
                if expression.lstrip().startswith("*") or "->" in expression:
                    facts.append(
                        {
                            **base,
                            "kind": "pointer_dereference",
                            "expression": expression,
                            "identifiers": _identifier_names(node, source),
                            "text": expression,
                        }
                    )
            if language in {"c", "cpp"} and node.type == "array_declarator":
                declarator = node.child_by_field_name("declarator")
                size = node.child_by_field_name("size")
                facts.append(
                    {
                        **base,
                        "kind": "array_declaration",
                        "name": _declarator_name(declarator, source),
                        "size": _text(size, source, limit=120),
                        "size_identifiers": _identifier_names(size, source),
                        "text": _text(node, source),
                    }
                )
        priority = {
            "condition": 0,
            "array_declaration": 1,
            "call": 2,
            "assignment": 3,
            "index": 4,
            "pointer_dereference": 5,
        }
        unique: dict[tuple[Any, ...], dict[str, Any]] = {}
        for fact in facts:
            key = (
                fact.get("kind"),
                fact.get("line"),
                fact.get("column"),
                fact.get("callee"),
                fact.get("text") or fact.get("expression"),
            )
            unique.setdefault(key, fact)
        return sorted(
            unique.values(),
            key=lambda item: (
                int(item.get("line", 0)),
                priority.get(str(item.get("kind")), 9),
                int(item.get("column", 0)),
            ),
        )

    @staticmethod
    def _assignment(node: Node, source: bytes) -> dict[str, Any] | None:
        left = node.child_by_field_name("left") or node.child_by_field_name("declarator")
        right = node.child_by_field_name("right") or node.child_by_field_name("value")
        if left is None and node.type == "var_spec" and node.named_children:
            left = node.named_children[0]
            right = node.named_children[-1] if len(node.named_children) > 1 else None
        if left is None or right is None:
            return None
        targets = _identifier_names(left, source)
        return {
            "targets": targets,
            "expression": _text(right, source),
            "expression_identifiers": _identifier_names(right, source),
            "text": _text(node, source),
        }

    @staticmethod
    def _assigned_targets(call: Node, source: bytes, body: Node) -> list[str]:
        current = call.parent
        while current is not None and current != body:
            if current.type in _ASSIGNMENT_TYPES:
                assignment = NativeSourceParser._assignment(current, source)
                return list(assignment.get("targets", [])) if assignment else []
            if current.type in {"expression_statement", "return_statement"}:
                break
            current = current.parent
        return []

    @staticmethod
    def _dependencies(root: Node, source: bytes, language: str) -> list[str]:
        values: list[str] = []
        target_types = (
            frozenset({"preproc_include"})
            if language in {"c", "cpp"}
            else frozenset({"import_spec"})
        )
        for node in _walk(root):
            if node.type not in target_types:
                continue
            if language in {"c", "cpp"}:
                path = node.child_by_field_name("path")
                raw = _text(path, source, limit=200) or _text(node, source, limit=200)
                value = re.sub(r"^#\s*include\s*", "", raw).strip('<>"')
            else:
                path = node.child_by_field_name("path")
                raw = _text(path, source, limit=200) or _text(node, source, limit=200)
                value = raw.strip('"`')
            if value and value not in values:
                values.append(value)
        return sorted(values)


__all__ = ["NativeSourceParseError", "NativeSourceParser"]
