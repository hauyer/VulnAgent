"""Explainable Python source auditing based on a parsed project inventory.

The auditor consumes only files already selected by ``SourceAnalysisResult``.
It re-opens those Python files for security-specific AST inspection, never
executes project code, and does not perform project discovery or parsing for
other languages.
"""

from __future__ import annotations

import ast
import logging
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from vulnagent.contracts import (
    SourceAnalysisResult,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)
from vulnagent.utils.ids import new_vulnerability_id

from .rules import (
    AuditRule,
    COMMAND_INJECTION,
    DYNAMIC_CODE_EXECUTION,
    PATH_TRAVERSAL,
    SQL_INJECTION,
    UNSAFE_DESERIALIZATION,
)

LOGGER = logging.getLogger(__name__)

_DEFAULT_MAX_FILE_BYTES = 1_000_000
_ALL_CATEGORIES = frozenset(
    {"command", "sql", "path", "deserialization", "code_execution"}
)

_COMMAND_SINKS = frozenset({"os.system", "os.popen"})
_SUBPROCESS_SINKS = frozenset(
    {
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
    }
)
_DESERIALIZATION_SINKS = frozenset(
    {
        "pickle.load",
        "pickle.loads",
        "marshal.load",
        "marshal.loads",
        "dill.load",
        "dill.loads",
        "yaml.load",
    }
)
_PATH_SINKS = frozenset(
    {
        "open",
        "io.open",
        "os.open",
        "pathlib.Path",
        "flask.send_file",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.move",
        "shutil.rmtree",
    }
)
_CODE_EXECUTION_SINKS = frozenset({"eval", "exec", "builtins.eval", "builtins.exec"})
_SOURCE_CALLS = frozenset(
    {
        "input",
        "builtins.input",
        "os.getenv",
        "os.environ.get",
        "flask.request.get_json",
    }
)
_REQUEST_SOURCE_SUFFIXES = (
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.cookies.get",
    "request.headers.get",
    "request.get_json",
)
_SOURCE_ATTRIBUTES = frozenset(
    {
        "request.args",
        "request.form",
        "request.values",
        "request.cookies",
        "request.headers",
        "request.json",
        "sys.argv",
        "os.environ",
    }
)
_SANITIZERS: dict[str, str] = {
    "shlex.quote": "command",
    "os.path.basename": "path",
    "werkzeug.utils.secure_filename": "path",
}
_ROUTE_DECORATORS = frozenset({"route", "get", "post", "put", "patch", "delete"})


@dataclass(frozen=True, slots=True)
class _Taint:
    origins: frozenset[str] = frozenset()
    trail: tuple[str, ...] = ()
    unsafe_for: frozenset[str] = frozenset()

    @classmethod
    def source(cls, origin: str, line: int | None) -> "_Taint":
        marker = f"{origin}@{line}" if line is not None else origin
        return cls(
            origins=frozenset({origin}),
            trail=(marker,),
            unsafe_for=_ALL_CATEGORIES,
        )

    def sanitized(self, category: str, sanitizer: str) -> "_Taint":
        return _Taint(
            origins=self.origins,
            trail=(*self.trail, f"sanitized:{sanitizer}"),
            unsafe_for=self.unsafe_for - {category},
        )

    def through(self, marker: str) -> "_Taint":
        if not self.origins:
            return self
        return _Taint(
            origins=self.origins,
            trail=(*self.trail, marker),
            unsafe_for=self.unsafe_for,
        )

    def is_unsafe_for(self, category: str) -> bool:
        return bool(self.origins) and category in self.unsafe_for


def _combine(items: Iterable[_Taint]) -> _Taint:
    origins: set[str] = set()
    unsafe_for: set[str] = set()
    trail: list[str] = []
    for item in items:
        origins.update(item.origins)
        unsafe_for.update(item.unsafe_for)
        for marker in item.trail:
            if marker not in trail:
                trail.append(marker)
    return _Taint(
        origins=frozenset(origins),
        trail=tuple(trail),
        unsafe_for=frozenset(unsafe_for),
    )


@dataclass(frozen=True, slots=True)
class _Match:
    rule: AuditRule
    file_path: str
    function_name: str | None
    module_name: str
    line: int
    end_line: int
    column: int
    sink: str
    snippet: str
    taint: _Taint
    dynamic_only: bool


def _expression_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _expression_name(node.value)
        return f"{owner}.{node.attr}" if owner else node.attr
    return None


def _is_literal(node: ast.AST) -> bool:
    try:
        ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False
    return True


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    for item in call.keywords:
        if item.arg == name:
            return item.value
    return None


def _literal_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _yaml_uses_safe_loader(call: ast.Call, resolve_name) -> bool:
    loader = _keyword(call, "Loader") or _keyword(call, "loader")
    if loader is None:
        return False
    name = resolve_name(_expression_name(loader) or "")
    return name in {"yaml.SafeLoader", "yaml.CSafeLoader"}


class _FileAuditor:
    """Stateful, intraprocedural auditor for one Python syntax tree."""

    def __init__(
        self,
        *,
        result: SourceAnalysisResult,
        displayed_path: str,
        source_lines: list[str],
        aliases: Mapping[str, str],
    ) -> None:
        self.result = result
        self.displayed_path = displayed_path
        self.source_lines = source_lines
        self.aliases = aliases
        self.module_name = Path(displayed_path).with_suffix("").as_posix().replace("/", ".")
        if self.module_name.endswith(".__init__"):
            self.module_name = self.module_name.removesuffix(".__init__")
        self.matches: list[_Match] = []

    def audit(self, tree: ast.Module) -> list[_Match]:
        self._scan_block(tree.body, {}, None)
        return self.matches

    def _resolve_name(self, raw: str) -> str:
        if not raw:
            return raw
        head, separator, tail = raw.partition(".")
        target = self.aliases.get(head)
        if target is None:
            return raw
        return f"{target}.{tail}" if separator else target

    def _source_origin(self, resolved: str) -> str | None:
        if resolved in _SOURCE_CALLS:
            return resolved
        if resolved.endswith(_REQUEST_SOURCE_SUFFIXES):
            return resolved
        return None

    def _taint(self, node: ast.AST | None, state: Mapping[str, _Taint]) -> _Taint:
        if node is None:
            return _Taint()
        if isinstance(node, ast.Name):
            return state.get(node.id, _Taint())
        if isinstance(node, ast.Constant):
            return _Taint()
        if isinstance(node, ast.Attribute):
            resolved = self._resolve_name(_expression_name(node) or "")
            if resolved in _SOURCE_ATTRIBUTES or resolved.endswith(tuple(_SOURCE_ATTRIBUTES)):
                return _Taint.source(resolved, getattr(node, "lineno", None))
            return self._taint(node.value, state)
        if isinstance(node, ast.Subscript):
            resolved = self._resolve_name(_expression_name(node.value) or "")
            if resolved in _SOURCE_ATTRIBUTES or resolved.endswith(tuple(_SOURCE_ATTRIBUTES)):
                return _Taint.source(resolved, getattr(node, "lineno", None))
            return _combine((self._taint(node.value, state), self._taint(node.slice, state)))
        if isinstance(node, ast.Call):
            raw = _expression_name(node.func) or ""
            resolved = self._resolve_name(raw)
            origin = self._source_origin(resolved)
            if origin is not None:
                return _Taint.source(origin, getattr(node, "lineno", None))
            values = [self._taint(item, state) for item in node.args]
            values.extend(self._taint(item.value, state) for item in node.keywords)
            if isinstance(node.func, ast.Attribute):
                values.append(self._taint(node.func.value, state))
            combined = _combine(values)
            category = _SANITIZERS.get(resolved)
            if category is not None:
                return combined.sanitized(category, resolved)
            return combined.through(f"call:{resolved}@{getattr(node, 'lineno', '?')}")
        if isinstance(node, ast.NamedExpr):
            return self._taint(node.value, state)
        if isinstance(node, ast.FormattedValue):
            return self._taint(node.value, state)
        if isinstance(node, ast.JoinedStr):
            return _combine(self._taint(item, state) for item in node.values)
        if isinstance(node, ast.BinOp):
            return _combine((self._taint(node.left, state), self._taint(node.right, state)))
        if isinstance(node, ast.BoolOp):
            return _combine(self._taint(item, state) for item in node.values)
        if isinstance(node, ast.UnaryOp):
            return self._taint(node.operand, state)
        if isinstance(node, ast.IfExp):
            return _combine(
                (
                    self._taint(node.test, state),
                    self._taint(node.body, state),
                    self._taint(node.orelse, state),
                )
            )
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return _combine(self._taint(item, state) for item in node.elts)
        if isinstance(node, ast.Dict):
            values = [self._taint(item, state) for item in node.keys if item is not None]
            values.extend(self._taint(item, state) for item in node.values)
            return _combine(values)
        if isinstance(node, ast.Await):
            return self._taint(node.value, state)
        if isinstance(node, ast.Compare):
            return _combine(
                [self._taint(node.left, state)]
                + [self._taint(item, state) for item in node.comparators]
            )
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return _combine(
                [self._taint(node.elt, state)]
                + [self._taint(item.iter, state) for item in node.generators]
            )
        if isinstance(node, ast.DictComp):
            return _combine(
                [self._taint(node.key, state), self._taint(node.value, state)]
                + [self._taint(item.iter, state) for item in node.generators]
            )
        return _Taint()

    def _inspect_expression(
        self,
        node: ast.AST | None,
        state: Mapping[str, _Taint],
        function_name: str | None,
    ) -> None:
        if node is None:
            return
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                self._inspect_call(item, state, function_name)

    def _inspect_call(
        self,
        call: ast.Call,
        state: Mapping[str, _Taint],
        function_name: str | None,
    ) -> None:
        raw = _expression_name(call.func) or ""
        sink = self._resolve_name(raw)
        first = call.args[0] if call.args else None

        if sink in _COMMAND_SINKS:
            self._maybe_add(COMMAND_INJECTION, call, first, sink, state, function_name)
            return

        if sink in _SUBPROCESS_SINKS:
            shell = _literal_true(_keyword(call, "shell"))
            argv_list = isinstance(first, (ast.List, ast.Tuple))
            if shell or not argv_list:
                self._maybe_add(COMMAND_INJECTION, call, first, sink, state, function_name)
            return

        if raw.rsplit(".", 1)[-1] in {"execute", "executemany"} and first is not None:
            query_taint = self._taint(first, state)
            if query_taint.is_unsafe_for("sql"):
                self._add(SQL_INJECTION, call, sink or raw, query_taint, False, function_name)
            return

        if sink in _PATH_SINKS:
            self._maybe_add(PATH_TRAVERSAL, call, first, sink, state, function_name, tainted_only=True)
            return

        if sink in _DESERIALIZATION_SINKS:
            if sink == "yaml.load" and _yaml_uses_safe_loader(call, self._resolve_name):
                return
            self._maybe_add(UNSAFE_DESERIALIZATION, call, first, sink, state, function_name)
            return

        if sink in _CODE_EXECUTION_SINKS:
            self._maybe_add(DYNAMIC_CODE_EXECUTION, call, first, sink, state, function_name)

    def _maybe_add(
        self,
        rule: AuditRule,
        call: ast.Call,
        argument: ast.expr | None,
        sink: str,
        state: Mapping[str, _Taint],
        function_name: str | None,
        *,
        tainted_only: bool = False,
    ) -> None:
        if argument is None:
            return
        taint = self._taint(argument, state)
        if taint.is_unsafe_for(rule.category):
            self._add(rule, call, sink, taint, False, function_name)
        elif not tainted_only and not _is_literal(argument) and not taint.origins:
            self._add(rule, call, sink, taint, True, function_name)

    def _add(
        self,
        rule: AuditRule,
        call: ast.Call,
        sink: str,
        taint: _Taint,
        dynamic_only: bool,
        function_name: str | None,
    ) -> None:
        line = int(getattr(call, "lineno", 1))
        end_line = int(getattr(call, "end_lineno", line))
        snippet = self.source_lines[line - 1].strip() if 0 < line <= len(self.source_lines) else ""
        self.matches.append(
            _Match(
                rule=rule,
                file_path=self.displayed_path,
                function_name=function_name,
                module_name=self.module_name,
                line=line,
                end_line=end_line,
                column=int(getattr(call, "col_offset", 0)),
                sink=sink,
                snippet=snippet[:500],
                taint=taint,
                dynamic_only=dynamic_only,
            )
        )

    def _scan_block(
        self,
        statements: Iterable[ast.stmt],
        state: dict[str, _Taint],
        function_name: str | None,
    ) -> dict[str, _Taint]:
        current = dict(state)
        for statement in statements:
            current = self._scan_statement(statement, current, function_name)
        return current

    def _scan_statement(
        self,
        statement: ast.stmt,
        state: dict[str, _Taint],
        function_name: str | None,
    ) -> dict[str, _Taint]:
        current = dict(state)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._scan_function(statement)
            return current
        if isinstance(statement, ast.ClassDef):
            for item in statement.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._scan_function(item)
                elif not isinstance(item, ast.ClassDef):
                    current = self._scan_statement(item, current, function_name)
            return current
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            self._inspect_expression(value, current, function_name)
            taint = self._taint(value, current).through(
                f"assignment@{getattr(statement, 'lineno', '?')}"
            )
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                self._assign_target(target, taint, current)
            return current
        if isinstance(statement, ast.AugAssign):
            self._inspect_expression(statement.value, current, function_name)
            taint = _combine(
                (self._taint(statement.target, current), self._taint(statement.value, current))
            )
            self._assign_target(statement.target, taint, current)
            return current
        if isinstance(statement, ast.Expr):
            self._inspect_expression(statement.value, current, function_name)
            return current
        if isinstance(statement, ast.Return):
            self._inspect_expression(statement.value, current, function_name)
            return current
        if isinstance(statement, ast.If):
            self._inspect_expression(statement.test, current, function_name)
            left = self._scan_block(statement.body, current, function_name)
            right = self._scan_block(statement.orelse, current, function_name)
            return self._merge_states(current, left, right)
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            self._inspect_expression(statement.iter, current, function_name)
            loop_state = dict(current)
            self._assign_target(statement.target, self._taint(statement.iter, current), loop_state)
            loop_state = self._scan_block(statement.body, loop_state, function_name)
            else_state = self._scan_block(statement.orelse, current, function_name)
            return self._merge_states(current, loop_state, else_state)
        if isinstance(statement, ast.While):
            self._inspect_expression(statement.test, current, function_name)
            body = self._scan_block(statement.body, current, function_name)
            other = self._scan_block(statement.orelse, current, function_name)
            return self._merge_states(current, body, other)
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                self._inspect_expression(item.context_expr, current, function_name)
                if item.optional_vars is not None:
                    self._assign_target(item.optional_vars, self._taint(item.context_expr, current), current)
            return self._scan_block(statement.body, current, function_name)
        if isinstance(statement, ast.Try):
            states = [self._scan_block(statement.body, current, function_name)]
            states.extend(
                self._scan_block(handler.body, current, function_name)
                for handler in statement.handlers
            )
            states.append(self._scan_block(statement.orelse, current, function_name))
            merged = self._merge_states(current, *states)
            return self._scan_block(statement.finalbody, merged, function_name)
        if isinstance(statement, ast.Delete):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    current.pop(target.id, None)
            return current

        for _, value in ast.iter_fields(statement):
            if isinstance(value, ast.expr):
                self._inspect_expression(value, current, function_name)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.expr):
                        self._inspect_expression(item, current, function_name)
        return current

    def _scan_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        function_name = self._function_name(node)
        state: dict[str, _Taint] = {}
        if self._is_route(node):
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if node.args.vararg is not None:
                arguments.append(node.args.vararg)
            if node.args.kwarg is not None:
                arguments.append(node.args.kwarg)
            for argument in arguments:
                if argument.arg not in {"self", "cls"}:
                    state[argument.arg] = _Taint.source(
                        f"route_parameter:{argument.arg}", node.lineno
                    )
        self._scan_block(node.body, state, function_name)

    def _function_name(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        containing = [
            item
            for item in self.result.symbols
            if item.get("file") == self.displayed_path
            and item.get("kind") in {"function", "method"}
            and int(item.get("line", -1)) == node.lineno
        ]
        if containing:
            return str(containing[0].get("qualified_name") or node.name)
        return f"{self.module_name}.{node.name}" if self.module_name else node.name

    def _is_route(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = _expression_name(target)
            if name and name.rsplit(".", 1)[-1].casefold() in _ROUTE_DECORATORS:
                return True
        return False

    @staticmethod
    def _assign_target(target: ast.AST, taint: _Taint, state: dict[str, _Taint]) -> None:
        if isinstance(target, ast.Name):
            if taint.origins:
                state[target.id] = taint
            else:
                state.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                _FileAuditor._assign_target(item, taint, state)

    @staticmethod
    def _merge_states(*states: Mapping[str, _Taint]) -> dict[str, _Taint]:
        names = {name for state in states for name in state}
        merged: dict[str, _Taint] = {}
        for name in names:
            value = _combine(state[name] for state in states if name in state)
            if value.origins:
                merged[name] = value
        return merged


class PythonSourceAuditor:
    """Find explainable Python vulnerability candidates without executing code."""

    async def audit(self, result: SourceAnalysisResult) -> list[VulnerabilityCandidate]:
        root = Path(result.project_path).expanduser()
        if not root.exists():
            LOGGER.warning("Source audit skipped missing project path: %s", root)
            return []

        root = root.resolve()
        matches: list[_Match] = []
        for displayed_path in sorted(set(result.files)):
            path = self._resolve_inventory_path(root, displayed_path)
            if path is None or path.suffix.casefold() not in {".py", ".pyi"}:
                continue
            parsed = self._read_tree(path, displayed_path, self._max_file_bytes(result))
            if parsed is None:
                continue
            tree, source = parsed
            aliases = self._aliases_for(result, displayed_path)
            matches.extend(
                _FileAuditor(
                    result=result,
                    displayed_path=displayed_path,
                    source_lines=source.splitlines(),
                    aliases=aliases,
                ).audit(tree)
            )

        unique: dict[tuple[str, int, str, str], _Match] = {}
        for match in matches:
            key = (match.file_path, match.line, match.rule.rule_id, match.sink)
            unique.setdefault(key, match)

        ordered = sorted(
            unique.values(),
            key=lambda item: (item.file_path, item.line, item.rule.rule_id, item.sink),
        )
        return [self._candidate(result, item) for item in ordered]

    @staticmethod
    def _resolve_inventory_path(root: Path, displayed_path: str) -> Path | None:
        relative = Path(displayed_path)
        if relative.is_absolute():
            LOGGER.warning("Source audit rejected absolute inventory path: %s", displayed_path)
            return None
        candidate = root if root.is_file() and relative.name == root.name else root / relative
        try:
            resolved = candidate.resolve()
            if root.is_file():
                allowed = resolved == root
            else:
                allowed = resolved.is_relative_to(root)
        except (OSError, RuntimeError):
            allowed = False
            resolved = candidate
        if not allowed:
            LOGGER.warning("Source audit rejected path outside project: %s", displayed_path)
            return None
        if not resolved.is_file():
            LOGGER.warning("Source audit skipped missing inventory file: %s", displayed_path)
            return None
        return resolved

    @staticmethod
    def _read_tree(
        path: Path,
        displayed_path: str,
        max_file_bytes: int,
    ) -> tuple[ast.Module, str] | None:
        try:
            if path.stat().st_size > max_file_bytes:
                LOGGER.warning("Source audit skipped oversized file: %s", displayed_path)
                return None
            with tokenize.open(path) as source_file:
                source = source_file.read()
            return ast.parse(source, filename=displayed_path), source
        except (OSError, SyntaxError, UnicodeError) as error:
            LOGGER.warning("Source audit skipped %s: %s", displayed_path, error)
            return None

    @staticmethod
    def _max_file_bytes(result: SourceAnalysisResult) -> int:
        raw = result.metadata.get("max_file_bytes", _DEFAULT_MAX_FILE_BYTES)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return _DEFAULT_MAX_FILE_BYTES
        return value if value > 0 else _DEFAULT_MAX_FILE_BYTES

    @staticmethod
    def _aliases_for(result: SourceAnalysisResult, displayed_path: str) -> dict[str, str]:
        imports = result.metadata.get("imports", {})
        entries = imports.get(displayed_path, []) if isinstance(imports, Mapping) else []
        aliases: dict[str, str] = {}
        for item in entries if isinstance(entries, list) else []:
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("name") or "")
            module = str(item.get("module") or "")
            asname = item.get("asname")
            if item.get("is_from"):
                bound = str(asname or name)
                target = ".".join(part for part in (module, name) if part)
            else:
                bound = str(asname or name.split(".", 1)[0])
                target = module or name
            if bound and target:
                aliases[bound] = target
        return aliases

    @staticmethod
    def _candidate(
        result: SourceAnalysisResult,
        match: _Match,
    ) -> VulnerabilityCandidate:
        if match.taint.origins:
            sources = sorted(match.taint.origins)
            source_text = ", ".join(sources)
            reason = f"Data from {source_text} reaches {match.sink}."
            confidence = match.rule.tainted_confidence
        else:
            sources = ["dynamic_value"]
            reason = f"A non-literal value reaches dangerous API {match.sink}."
            confidence = match.rule.dynamic_confidence
        return VulnerabilityCandidate(
            vulnerability_id=new_vulnerability_id(),
            task_id=result.task_id,
            title=match.rule.title,
            vulnerability_type=match.rule.vulnerability_type,
            cwe_id=match.rule.cwe_id,
            description=(
                f"{reason} This is a discovery candidate and requires independent verification."
            ),
            target_id=result.target_id,
            location=VulnerabilityLocation(
                file_path=match.file_path,
                function_name=match.function_name,
                line_start=match.line,
                line_end=match.end_line,
                module_name=match.module_name,
            ),
            source_agent="source_audit",
            source_type="source",
            producer="PythonSourceAuditor",
            confidence=confidence,
            severity=match.rule.severity,
            metadata={
                "analysis_engine": "python_ast_rules",
                "rule_id": match.rule.rule_id,
                "category": match.rule.category,
                "sink": match.sink,
                "source_kinds": sources,
                "taint_path": list(match.taint.trail),
                "snippet": match.snippet,
                "column": match.column,
                "dynamic_only": match.dynamic_only,
                "limitations": [
                    "intraprocedural best-effort taint analysis",
                    "candidate requires independent verification",
                ],
            },
        )


__all__ = ["PythonSourceAuditor"]
