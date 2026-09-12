"""Defensive C/C++/Go taint analysis over the normalized parser IR.

The auditor consumes facts already stored in ``SourceAnalysisResult.metadata``.
It does not compile or execute the target, invoke a debugger, access the
network, or create proof-of-concept/exploit material.  Matches remain
``CANDIDATE`` records until a separate verification stage reviews them.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from vulnagent.contracts import (
    SourceAnalysisResult,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)
from vulnagent.utils.ids import new_vulnerability_id

from .auditor import PythonSourceAuditor
from .rules import (
    AuditRule,
    NATIVE_ARRAY_BOUNDS,
    NATIVE_DANGEROUS_COPY,
    NATIVE_INPUT_VALIDATION,
    NATIVE_INTEGER_OVERFLOW,
    NATIVE_NULL_DEREFERENCE,
    NATIVE_RESOURCE_LEAK,
    NATIVE_INTERFACE_ACCESS,
    NATIVE_CONFIG_AUTHORIZATION,
)

_UNBOUNDED_COPY_CALLS = frozenset({"gets", "strcpy", "strcat", "sprintf", "vsprintf"})
_BOUNDED_COPY_CALLS = frozenset({"memcpy", "memmove", "strncpy", "strncat"})
_ALLOCATION_CALLS = frozenset(
    {"malloc", "calloc", "realloc", "aligned_alloc", "new", "make"}
)
_BUFFER_INPUT_CALLS: Mapping[str, tuple[int, ...]] = {
    "recv": (1,),
    "recvfrom": (1,),
    "read": (1,),
    "fread": (0,),
    "fgets": (0,),
    "gets": (0,),
    "scanf": (1,),
    "fscanf": (2,),
    "sscanf": (2,),
    "Read": (0,),
    "Decode": (0,),
    "Bind": (0,),
}
_RETURN_INPUT_CALLS = frozenset(
    {
        "getenv",
        "FormValue",
        "Get",
        "Param",
        "Query",
        "ReadString",
        "ReadBytes",
    }
)
_ARITHMETIC_RE = re.compile(r"(?:\+|-|\*|<<|>>)")
_COMPARISON_RE = re.compile(r"(?:<=|>=|==|!=|<|>)")
_INTEGER_LITERAL_RE = re.compile(r"^\s*(0[xX][0-9a-fA-F]+|\d+)[uUlL]*\s*$")
_RESOURCE_ACQUIRE_CALLS: Mapping[str, str] = {
    "fopen": "fclose",
    "open": "close",
    "socket": "close",
    "malloc": "free",
    "calloc": "free",
    "realloc": "free",
    "Open": "Close",
}
_CONFIG_MUTATION_CALLS = frozenset(
    {"SetConfig", "UpdateConfig", "ApplyConfig", "SaveConfig", "WriteConfig"}
)
_PRIVILEGED_OPERATION_CALLS = frozenset(
    {"Shutdown", "Restart", "Reload", "Delete", "Remove", "Install", "StopServer", "StartServer"}
)
_AUTH_GUARD_RE = re.compile(
    r"(?:auth|authori[sz]|permission|privilege|admin|role|token|session|credential)",
    re.IGNORECASE,
)
_HANDLER_RE = re.compile(r"(?:handler|endpoint|admin|manage|api)", re.IGNORECASE)


def _simple_name(name: str) -> str:
    """Return the terminal part of a C++/Go/C call spelling."""

    value = name.rsplit("::", 1)[-1]
    value = value.rsplit(".", 1)[-1]
    value = value.rsplit("->", 1)[-1]
    return value.strip()


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))]


def _identifier_groups(value: Any) -> list[list[str]]:
    if not isinstance(value, list):
        return []
    return [_string_list(item) for item in value]


def _literal_integer(expression: str) -> int | None:
    match = _INTEGER_LITERAL_RE.fullmatch(expression)
    if match is None:
        return None
    try:
        return int(match.group(1), 0)
    except ValueError:  # pragma: no cover - regex already constrains input
        return None


@dataclass(frozen=True, slots=True)
class _Taint:
    """One compact explainable taint value."""

    origins: tuple[str, ...] = ()
    trail: tuple[str, ...] = ()

    @classmethod
    def source(cls, label: str, line: int) -> "_Taint":
        return cls(origins=(label,), trail=(f"source:{label}@{line}",))

    def through(self, label: str) -> "_Taint":
        if not self.origins:
            return self
        return _Taint(self.origins, (*self.trail, label))


def _merge_taint(values: Iterable[_Taint]) -> _Taint:
    origins: list[str] = []
    trail: list[str] = []
    for value in values:
        for origin in value.origins:
            if origin not in origins:
                origins.append(origin)
        for step in value.trail:
            if step not in trail:
                trail.append(step)
    return _Taint(tuple(origins), tuple(trail))


@dataclass(frozen=True, slots=True)
class _NativeMatch:
    rule: AuditRule
    file_path: str
    language: str
    function_name: str
    line: int
    end_line: int
    column: int
    sink: str
    reason: str
    snippet: str
    taint: _Taint
    cfg_path: tuple[Mapping[str, Any], ...]
    checked: bool
    extra: Mapping[str, Any]


class _FunctionAuditor:
    """Run a deterministic intraprocedural data-flow pass over one function."""

    def __init__(
        self,
        *,
        file_path: str,
        language: str,
        function: Mapping[str, Any],
    ) -> None:
        self.file_path = file_path
        self.language = language
        self.function = function
        self.function_name = str(function.get("qualified_name") or function.get("name") or "")
        self.state: dict[str, _Taint] = {}
        self.matches: list[_NativeMatch] = []
        self.conditions: list[Mapping[str, Any]] = []
        self.arrays: dict[str, int] = {}
        self.heap_buffers: dict[str, int | None] = {}

    def audit(self) -> list[_NativeMatch]:
        for parameter in self._mappings(self.function.get("parameters")):
            name = str(parameter.get("name") or "")
            if name and name != "<anonymous>":
                parameter_line = int(
                    parameter.get("line") or self.function.get("line_start") or 1
                )
                self.state[name] = _Taint.source(
                    f"api_parameter:{name}", parameter_line
                )

        facts = sorted(
            self._mappings(self.function.get("facts")),
            key=lambda item: (int(item.get("line") or 0), int(item.get("column") or 0)),
        )
        self.conditions = [item for item in facts if item.get("kind") == "condition"]
        for fact in facts:
            kind = str(fact.get("kind") or "")
            if kind == "array_declaration":
                self._record_array(fact)
            elif kind == "assignment":
                self._propagate_assignment(fact)
            elif kind == "call":
                self._inspect_call(fact)
            elif kind == "index":
                self._inspect_index(fact)
            elif kind == "pointer_dereference":
                self._inspect_dereference(fact)
        self._inspect_resource_lifetimes(facts)
        self._inspect_access_control(facts)
        return self.matches

    def _record_array(self, fact: Mapping[str, Any]) -> None:
        name = str(fact.get("name") or "")
        capacity = _literal_integer(str(fact.get("size") or ""))
        if name and capacity is not None:
            self.arrays[name] = capacity

    def _propagate_assignment(self, fact: Mapping[str, Any]) -> None:
        taint = self._taint_for(_string_list(fact.get("expression_identifiers")))
        line = int(fact.get("line") or 1)
        for target in _string_list(fact.get("targets")):
            if taint.origins:
                self.state[target] = taint.through(f"assignment:{target}@{line}")
            else:
                self.state.pop(target, None)

    def _inspect_call(self, fact: Mapping[str, Any]) -> None:
        raw_callee = str(fact.get("callee") or "")
        callee = _simple_name(raw_callee)
        line = int(fact.get("line") or 1)
        arguments = _string_list(fact.get("arguments"))
        identifiers = _identifier_groups(fact.get("argument_identifiers"))

        self._mark_input_sources(fact, callee, identifiers, line)

        if callee in _ALLOCATION_CALLS:
            literal_capacity = _literal_integer(arguments[-1]) if arguments else None
            for target in _string_list(fact.get("assigned_to")):
                self.heap_buffers[target] = literal_capacity

        if callee in _UNBOUNDED_COPY_CALLS:
            self._inspect_unbounded_copy(fact, callee, arguments, identifiers)
        elif callee in _BOUNDED_COPY_CALLS:
            self._inspect_bounded_copy(fact, callee, arguments, identifiers)

        if callee in _ALLOCATION_CALLS:
            self._inspect_allocation(fact, callee, arguments, identifiers)

    def _mark_input_sources(
        self,
        fact: Mapping[str, Any],
        callee: str,
        identifiers: list[list[str]],
        line: int,
    ) -> None:
        for target in _string_list(fact.get("assigned_to")):
            if callee in _RETURN_INPUT_CALLS:
                self.state[target] = _Taint.source(f"input_call:{callee}", line).through(
                    f"assignment:{target}@{line}"
                )
        for position in _BUFFER_INPUT_CALLS.get(callee, ()):
            if position >= len(identifiers):
                continue
            for target in identifiers[position]:
                self.state[target] = _Taint.source(f"input_call:{callee}", line).through(
                    f"output_argument:{target}@{line}"
                )

    def _inspect_unbounded_copy(
        self,
        fact: Mapping[str, Any],
        callee: str,
        arguments: list[str],
        identifiers: list[list[str]],
    ) -> None:
        source_positions = range(1, len(identifiers)) if callee != "gets" else range(0, 1)
        taint = _merge_taint(
            self._taint_for(identifiers[position])
            for position in source_positions
            if position < len(identifiers)
        )
        destination = arguments[0] if arguments else ""
        destination_name = identifiers[0][0] if identifiers and identifiers[0] else destination
        checked = all(
            self._is_validated(origin, int(fact.get("line") or 1))
            for origin in self._tainted_names(identifiers)
        ) if taint.origins else False
        if taint.origins or callee in {"gets", "strcpy", "sprintf", "vsprintf"}:
            reason = (
                f"Tainted input reaches unbounded function {callee}."
                if taint.origins
                else f"Unbounded function {callee} writes to {destination_name or 'a destination buffer'}."
            )
            self._add(
                NATIVE_DANGEROUS_COPY,
                fact,
                callee,
                reason,
                taint.through(f"sink:{callee}@{int(fact.get('line') or 1)}"),
                checked,
                {
                    "destination": destination_name,
                    "destination_capacity": self.arrays.get(destination_name),
                    "memory_region": (
                        "stack" if destination_name in self.arrays
                        else "heap" if destination_name in self.heap_buffers
                        else "unknown"
                    ),
                },
            )
            if taint.origins and not checked:
                self._add_missing_validation(fact, callee, taint)

    def _inspect_bounded_copy(
        self,
        fact: Mapping[str, Any],
        callee: str,
        arguments: list[str],
        identifiers: list[list[str]],
    ) -> None:
        if len(arguments) < 3:
            return
        destination_name = identifiers[0][0] if identifiers and identifiers[0] else arguments[0]
        length_expression = arguments[2]
        length_names = identifiers[2] if len(identifiers) > 2 else []
        length_taint = self._taint_for(length_names)
        capacity = self.arrays.get(destination_name)
        if capacity is None:
            capacity = self.heap_buffers.get(destination_name)
        literal_length = _literal_integer(length_expression)
        checked = self._expression_is_bounded(
            length_expression, length_names, destination_name, int(fact.get("line") or 1)
        )
        mismatch = capacity is not None and literal_length is not None and literal_length > capacity
        if not mismatch and (not length_taint.origins or checked):
            return
        reason = (
            f"Copy length {literal_length} exceeds fixed array capacity {capacity}."
            if mismatch
            else f"Tainted copy length for {callee} has no preceding range/bounds check."
        )
        taint = length_taint.through(f"sink:{callee}.length@{int(fact.get('line') or 1)}")
        self._add(
            NATIVE_DANGEROUS_COPY,
            fact,
            callee,
            reason,
            taint,
            checked,
            {
                "destination": destination_name,
                "destination_capacity": capacity,
                "copy_length": length_expression,
                "memory_region": (
                    "stack" if destination_name in self.arrays
                    else "heap" if destination_name in self.heap_buffers
                    else "unknown"
                ),
            },
        )
        if length_taint.origins and not checked:
            self._add_missing_validation(fact, f"{callee}.length", length_taint)

    def _inspect_allocation(
        self,
        fact: Mapping[str, Any],
        callee: str,
        arguments: list[str],
        identifiers: list[list[str]],
    ) -> None:
        relevant = list(range(len(arguments)))
        if callee == "realloc" and len(arguments) > 1:
            relevant = [1]
        expressions = [arguments[index] for index in relevant]
        names = [name for index in relevant if index < len(identifiers) for name in identifiers[index]]
        taint = self._taint_for(names)
        arithmetic = callee == "calloc" and len(expressions) >= 2
        arithmetic = arithmetic or any(
            _ARITHMETIC_RE.search(expression) for expression in expressions
        )
        line = int(fact.get("line") or 1)
        checked = all(self._is_validated(name, line) for name in names if name in self.state)
        if not taint.origins or not arithmetic or checked:
            return
        self._add(
            NATIVE_INTEGER_OVERFLOW,
            fact,
            callee,
            "A tainted arithmetic size expression reaches an allocation without an overflow/range guard.",
            taint.through(f"sink:{callee}.size@{line}"),
            False,
            {"size_expressions": expressions},
        )
        self._add_missing_validation(fact, f"{callee}.size", taint)

    def _inspect_index(self, fact: Mapping[str, Any]) -> None:
        names = _string_list(fact.get("index_identifiers"))
        taint = self._taint_for(names)
        if not taint.origins:
            return
        line = int(fact.get("line") or 1)
        checked = all(self._is_validated(name, line) for name in names if name in self.state)
        if checked:
            return
        expression = str(fact.get("index") or "")
        sink = f"index:{fact.get('container') or '<array>'}"
        self._add(
            NATIVE_ARRAY_BOUNDS,
            fact,
            sink,
            "A tainted array/slice index is used without a preceding range guard.",
            taint.through(f"sink:{sink}@{line}"),
            False,
            {"index_expression": expression},
        )
        if _ARITHMETIC_RE.search(expression):
            self._add(
                NATIVE_INTEGER_OVERFLOW,
                fact,
                sink,
                "A tainted arithmetic expression is used in an array/slice index without a range guard.",
                taint.through(f"arithmetic_index@{line}"),
                False,
                {"index_expression": expression},
            )
        self._add_missing_validation(fact, sink, taint)

    def _inspect_dereference(self, fact: Mapping[str, Any]) -> None:
        names = _string_list(fact.get("identifiers"))
        taint = self._taint_for(names)
        if not taint.origins:
            return
        line = int(fact.get("line") or 1)
        checked = all(self._is_validated(name, line) for name in names if name in self.state)
        if checked:
            return
        expression = str(fact.get("expression") or "")
        self._add(
            NATIVE_NULL_DEREFERENCE,
            fact,
            "pointer_dereference",
            "A pointer influenced by an API parameter is dereferenced without an observed null guard.",
            taint.through(f"sink:pointer_dereference@{line}"),
            False,
            {"dereference_expression": expression},
        )

    def _inspect_resource_lifetimes(self, facts: list[Mapping[str, Any]]) -> None:
        released: set[str] = set()
        for fact in facts:
            if fact.get("kind") != "call":
                continue
            callee = _simple_name(str(fact.get("callee") or ""))
            if callee not in {"free", "close", "fclose", "Close"}:
                continue
            identifiers = _identifier_groups(fact.get("argument_identifiers"))
            released.update(name for group in identifiers for name in group)
            raw_callee = str(fact.get("callee") or "")
            if raw_callee.endswith(".Close") or raw_callee.endswith("->Close"):
                released.update(raw_callee.replace("->", ".").split(".")[:-1])
        for fact in facts:
            if fact.get("kind") != "call":
                continue
            callee = _simple_name(str(fact.get("callee") or ""))
            expected_release = _RESOURCE_ACQUIRE_CALLS.get(callee)
            targets = _string_list(fact.get("assigned_to"))
            if expected_release is None or not targets or any(target in released for target in targets):
                continue
            line = int(fact.get("line") or 1)
            self._add(
                NATIVE_RESOURCE_LEAK,
                fact,
                f"resource:{callee}",
                f"Resource returned by {callee} has no observed matching {expected_release} in the function.",
                _Taint().through(f"resource_acquire:{callee}@{line}"),
                False,
                {"resource_variables": targets, "expected_release": expected_release},
            )

    def _inspect_access_control(self, facts: list[Mapping[str, Any]]) -> None:
        calls = [fact for fact in facts if fact.get("kind") == "call"]
        guarded = any(
            _AUTH_GUARD_RE.search(str(condition.get("expression") or ""))
            for condition in self.conditions
        ) or any(
            _AUTH_GUARD_RE.search(str(fact.get("callee") or ""))
            for fact in calls
        )
        if guarded:
            return
        for fact in calls:
            callee = _simple_name(str(fact.get("callee") or ""))
            if callee in _CONFIG_MUTATION_CALLS:
                identifiers = _identifier_groups(fact.get("argument_identifiers"))
                taint = self._taint_for(name for group in identifiers for name in group)
                line = int(fact.get("line") or 1)
                self._add(
                    NATIVE_CONFIG_AUTHORIZATION,
                    fact,
                    callee,
                    "A configuration mutation is reachable without an observed authentication or authorization guard.",
                    taint.through(f"sink:{callee}@{line}"),
                    False,
                    {"authorization_guard_observed": False},
                )
            elif _HANDLER_RE.search(self.function_name) and callee in _PRIVILEGED_OPERATION_CALLS:
                identifiers = _identifier_groups(fact.get("argument_identifiers"))
                taint = self._taint_for(name for group in identifiers for name in group)
                line = int(fact.get("line") or 1)
                self._add(
                    NATIVE_INTERFACE_ACCESS,
                    fact,
                    callee,
                    "A local service handler reaches a privileged operation without an observed access-control guard.",
                    taint.through(f"sink:{callee}@{line}"),
                    False,
                    {"authorization_guard_observed": False},
                )

    def _add_missing_validation(
        self,
        fact: Mapping[str, Any],
        sink: str,
        taint: _Taint,
    ) -> None:
        self._add(
            NATIVE_INPUT_VALIDATION,
            fact,
            sink,
            "Externally influenced data reaches a sensitive size/index/copy operation without an observed type, length, or range check.",
            taint.through(f"missing_validation:{sink}@{int(fact.get('line') or 1)}"),
            False,
            {},
        )

    def _expression_is_bounded(
        self,
        expression: str,
        names: list[str],
        destination: str,
        line: int,
    ) -> bool:
        compact = expression.replace(" ", "")
        if destination and f"sizeof({destination})" in compact:
            return True
        return bool(names) and all(self._is_validated(name, line) for name in names if name in self.state)

    def _is_validated(self, name: str, before_line: int) -> bool:
        if not name:
            return False
        token = re.compile(rf"\b{re.escape(name)}\b")
        for condition in self.conditions:
            line = int(condition.get("line") or 0)
            if line >= before_line:
                continue
            expression = str(condition.get("expression") or "")
            if not token.search(expression):
                continue
            if _COMPARISON_RE.search(expression) or "len(" in expression or "sizeof(" in expression:
                return True
        return False

    def _taint_for(self, names: Iterable[str]) -> _Taint:
        return _merge_taint(self.state[name] for name in names if name in self.state)

    def _tainted_names(self, groups: Iterable[Iterable[str]]) -> list[str]:
        return list(dict.fromkeys(name for group in groups for name in group if name in self.state))

    def _add(
        self,
        rule: AuditRule,
        fact: Mapping[str, Any],
        sink: str,
        reason: str,
        taint: _Taint,
        checked: bool,
        extra: Mapping[str, Any],
    ) -> None:
        self.matches.append(
            _NativeMatch(
                rule=rule,
                file_path=self.file_path,
                language=self.language,
                function_name=self.function_name,
                line=int(fact.get("line") or 1),
                end_line=int(fact.get("end_line") or fact.get("line") or 1),
                column=int(fact.get("column") or 0),
                sink=sink,
                reason=reason,
                snippet=str(fact.get("text") or fact.get("expression") or "")[:500],
                taint=taint,
                cfg_path=self._cfg_path(int(fact.get("line") or 1)),
                checked=checked,
                extra=dict(extra),
            )
        )

    def _cfg_path(self, sink_line: int) -> tuple[Mapping[str, Any], ...]:
        """Return a bounded entry-to-sink path over the normalized CFG."""

        cfg = self.function.get("cfg")
        if not isinstance(cfg, Mapping):
            return ()
        nodes = self._mappings(cfg.get("nodes"))
        edges = self._mappings(cfg.get("edges"))
        if not nodes:
            return ()
        by_id = {
            str(node.get("node_id")): node
            for node in nodes
            if node.get("node_id")
        }
        if not by_id:
            return ()
        start = str(nodes[0].get("node_id") or "")
        targets = {
            node_id
            for node_id, node in by_id.items()
            if int(node.get("line") or 0) == sink_line
        }
        if not start or not targets:
            return ()
        outgoing: dict[str, list[str]] = {}
        for edge in edges:
            source = str(edge.get("source") or "")
            target = str(edge.get("target") or "")
            if source in by_id and target in by_id:
                outgoing.setdefault(source, []).append(target)
        queue: deque[tuple[str, tuple[str, ...]]] = deque([(start, (start,))])
        visited = {start}
        selected: tuple[str, ...] = ()
        while queue:
            current, path = queue.popleft()
            if current in targets:
                selected = path
                break
            for target in outgoing.get(current, []):
                if target not in visited and len(path) < 64:
                    visited.add(target)
                    queue.append((target, (*path, target)))
        if not selected:
            selected = (next(iter(targets)),)
        return tuple(
            {
                "node_id": node_id,
                "node_type": str(by_id[node_id].get("node_type") or "statement"),
                "line": int(by_id[node_id].get("line") or 0),
                "text": str(by_id[node_id].get("text") or "")[:240],
            }
            for node_id in selected
        )

    @staticmethod
    def _mappings(value: Any) -> list[Mapping[str, Any]]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, Mapping)]


class NativeSourceAuditor:
    """Create candidate-only C/C++/Go findings from normalized AST/CFG facts."""

    async def audit(self, result: SourceAnalysisResult) -> list[VulnerabilityCandidate]:
        native = result.metadata.get("native_analysis")
        if not isinstance(native, Mapping):
            return []
        files = native.get("files")
        if not isinstance(files, Mapping):
            return []

        matches: list[_NativeMatch] = []
        for file_path in sorted(str(item) for item in files):
            file_ir = files.get(file_path)
            if not isinstance(file_ir, Mapping):
                continue
            language = str(file_ir.get("language") or "")
            functions = file_ir.get("functions")
            if not isinstance(functions, list):
                continue
            for function in functions:
                if isinstance(function, Mapping):
                    matches.extend(
                        _FunctionAuditor(
                            file_path=file_path,
                            language=language,
                            function=function,
                        ).audit()
                    )

        unique: dict[tuple[str, int, str, str], _NativeMatch] = {}
        for match in matches:
            unique.setdefault(
                (match.file_path, match.line, match.rule.rule_id, match.sink), match
            )
        ordered = sorted(
            unique.values(),
            key=lambda item: (item.file_path, item.line, item.rule.rule_id, item.sink),
        )
        return [self._candidate(result, match) for match in ordered]

    @staticmethod
    def _candidate(
        result: SourceAnalysisResult,
        match: _NativeMatch,
    ) -> VulnerabilityCandidate:
        sources = list(match.taint.origins) or ["static_structure"]
        extra = dict(match.extra)
        risk_subtype = None
        if match.rule.rule_id == NATIVE_DANGEROUS_COPY.rule_id:
            region = extra.get("memory_region")
            if region in {"stack", "heap"}:
                risk_subtype = f"{region}_buffer_overflow"
        integer_boundary_kind = None
        if match.rule.rule_id == NATIVE_INTEGER_OVERFLOW.rule_id:
            expressions = [
                *[str(item) for item in extra.get("size_expressions", [])],
                str(extra.get("index_expression") or ""),
            ]
            integer_boundary_kind = (
                "underflow_possible"
                if any("-" in expression for expression in expressions)
                else "overflow_possible"
            )
        confidence = (
            match.rule.tainted_confidence
            if match.taint.origins
            else match.rule.dynamic_confidence
        )
        return VulnerabilityCandidate(
            vulnerability_id=new_vulnerability_id(),
            task_id=result.task_id,
            title=match.rule.title,
            vulnerability_type=match.rule.vulnerability_type,
            cwe_id=match.rule.cwe_id,
            description=(
                f"{match.reason} This is a defensive static-analysis candidate "
                "and requires independent review."
            ),
            target_id=result.target_id,
            location=VulnerabilityLocation(
                file_path=match.file_path,
                function_name=match.function_name,
                line_start=match.line,
                line_end=match.end_line,
                module_name=match.file_path.rsplit(".", 1)[0].replace("/", "."),
            ),
            source_agent="source_audit",
            source_type="source",
            producer="NativeSourceAuditor",
            confidence=confidence,
            severity=match.rule.severity,
            metadata={
                "analysis_engine": "tree_sitter_native_rules",
                "audit_domain": "software_code",
                "language": match.language,
                "rule_id": match.rule.rule_id,
                "category": match.rule.category,
                "sink": match.sink,
                "source_kinds": sources,
                "taint_path": list(match.taint.trail),
                "cfg_path": [dict(item) for item in match.cfg_path],
                "snippet": match.snippet,
                "column": match.column,
                "guard_observed": match.checked,
                "risk_subtype": risk_subtype,
                "integer_boundary_kind": integer_boundary_kind,
                **extra,
                "limitations": [
                    "intraprocedural best-effort taint analysis",
                    "macros, aliases, pointer targets and dynamic dispatch may be incomplete",
                    "candidate requires independent verification",
                ],
            },
        )


class MultiLanguageSourceAuditor:
    """Compose Python AST rules with C/C++/Go normalized-IR rules."""

    def __init__(
        self,
        python_auditor: PythonSourceAuditor | None = None,
        native_auditor: NativeSourceAuditor | None = None,
    ) -> None:
        self.python_auditor = python_auditor or PythonSourceAuditor()
        self.native_auditor = native_auditor or NativeSourceAuditor()

    async def audit(self, result: SourceAnalysisResult) -> list[VulnerabilityCandidate]:
        findings = [
            *await self.python_auditor.audit(result),
            *await self.native_auditor.audit(result),
        ]
        return sorted(
            findings,
            key=lambda item: (
                item.location.file_path if item.location and item.location.file_path else "",
                item.location.line_start if item.location and item.location.line_start else 0,
                item.metadata.get("rule_id", ""),
            ),
        )


__all__ = ["MultiLanguageSourceAuditor", "NativeSourceAuditor"]
