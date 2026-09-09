"""Python project structure parser backed by the standard-library AST."""

from __future__ import annotations

import ast
import logging
import os
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from vulnagent.contracts import ProjectInput, SourceAnalysisResult

from .python_resolver import resolve_call_graph_for_files

LOGGER = logging.getLogger(__name__)

IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "build",
        "dist",
    }
)
_IGNORED_DIRECTORY_NAMES_CASEFOLDED = {
    name.casefold() for name in IGNORED_DIRECTORY_NAMES
}


def _expression_name(node: ast.expr) -> str | None:
    """Return a readable dotted name for a statically named expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _expression_name(node.value)
        return f"{owner}.{node.attr}" if owner else node.attr
    return None


class _CallCollector(ast.NodeVisitor):
    """Collect calls in one callable without entering nested definitions."""

    def __init__(self) -> None:
        self.calls: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        name = _expression_name(node.func)
        if name:
            self.calls.add(name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return


def _annotation_name(value: ast.expr | None) -> str | None:
    """Render a type annotation as source text (``None`` when absent)."""
    if value is None:
        return None
    try:
        return ast.unparse(value)
    except Exception:  # pragma: no cover - defensive, any expr is unparseable
        return None


def _expression_display(value: ast.expr) -> str:
    """Readable source text for a decorator/base expression."""
    name = _expression_name(value)
    if name:
        return name
    try:
        return ast.unparse(value)
    except Exception:  # pragma: no cover - defensive
        return "<expr>"


def _decorator_names(node: ast.AST) -> list[str]:
    return [_expression_display(value) for value in node.decorator_list]


def _parameter_entries(arguments: ast.arguments) -> list[dict[str, Any]]:
    """Flatten a function/method argument list into JSON-safe records."""
    entries: list[dict[str, Any]] = []
    positional = [*arguments.posonlyargs, *arguments.args]
    first_default = len(positional) - len(arguments.defaults)
    for index, argument in enumerate(positional):
        kind = (
            "positional_only"
            if index < len(arguments.posonlyargs)
            else "positional_or_keyword"
        )
        entries.append(
            {
                "name": argument.arg,
                "kind": kind,
                "has_default": index >= first_default,
                "annotation": _annotation_name(argument.annotation),
            }
        )
    if arguments.vararg is not None:
        entries.append(
            {
                "name": arguments.vararg.arg,
                "kind": "vararg",
                "has_default": False,
                "annotation": _annotation_name(arguments.vararg.annotation),
            }
        )
    for index, argument in enumerate(arguments.kwonlyargs):
        entries.append(
            {
                "name": argument.arg,
                "kind": "keyword_only",
                "has_default": arguments.kw_defaults[index] is not None,
                "annotation": _annotation_name(argument.annotation),
            }
        )
    if arguments.kwarg is not None:
        entries.append(
            {
                "name": arguments.kwarg.arg,
                "kind": "kwarg",
                "has_default": False,
                "annotation": _annotation_name(arguments.kwarg.annotation),
            }
        )
    return entries


def _is_main_guard(test: ast.expr) -> bool:
    """True for the canonical ``__name__ == "__main__"`` guard expression."""
    return (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def _main_guard_line(tree: ast.AST) -> int | None:
    """Line of the top-level ``if __name__ == "__main__"`` block, if any."""
    if not isinstance(tree, ast.Module):
        return None
    for statement in tree.body:
        if isinstance(statement, ast.If) and _is_main_guard(statement.test):
            return statement.lineno
    return None


def _entry_points(parsed_files: Iterable[Any]) -> list[dict[str, Any]]:
    """Files that define an executable entry point, sorted deterministically."""
    points = [
        {"file": parsed_file.displayed_path, "line": parsed_file.entry_point}
        for parsed_file in parsed_files
        if parsed_file.entry_point is not None
    ]
    points.sort(key=lambda point: (str(point["file"]), int(point["line"])))
    return points


class _SymbolVisitor(ast.NodeVisitor):
    """Extract classes, functions, methods, and their direct call sites."""

    def __init__(self, module: str, file_path: str) -> None:
        self.module = module
        self.file_path = file_path
        self.scope: list[tuple[str, str]] = []
        self.symbols: list[dict[str, Any]] = []
        self.call_graph: dict[str, set[str]] = {}

    def _qualified_name(self, name: str) -> str:
        parts = [self.module, *(scope_name for scope_name, _ in self.scope), name]
        return ".".join(part for part in parts if part)

    def _symbol(
        self,
        node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        kind: str,
        is_async: bool = False,
    ) -> dict[str, Any]:
        return {
            "name": node.name,
            "qualified_name": self._qualified_name(node.name),
            "kind": kind,
            "file": self.file_path,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "column": node.col_offset,
            "is_async": is_async,
        }

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        symbol = self._symbol(node, kind="class")
        symbol["bases"] = [
            _expression_display(base) for base in node.bases
        ]
        symbol["decorators"] = _decorator_names(node)
        self.symbols.append(symbol)
        self.scope.append((node.name, "class"))
        for statement in node.body:
            self.visit(statement)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_callable(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_callable(node, is_async=True)

    def _visit_callable(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        kind = "method" if self.scope and self.scope[-1][1] == "class" else "function"
        symbol = self._symbol(node, kind=kind, is_async=is_async)
        symbol["decorators"] = _decorator_names(node)
        symbol["parameters"] = _parameter_entries(node.args)
        symbol["return_annotation"] = _annotation_name(node.returns)
        self.symbols.append(symbol)

        collector = _CallCollector()
        for statement in node.body:
            collector.visit(statement)
        qualified_name = str(symbol["qualified_name"])
        self.call_graph.setdefault(qualified_name, set()).update(collector.calls)

        self.scope.append((node.name, "callable"))
        for statement in node.body:
            self.visit(statement)
        self.scope.pop()


def _module_name(relative_path: Path) -> str:
    parts = list(relative_path.with_suffix("").parts)
    if parts and parts[-1] == "__init__" and len(parts) > 1:
        parts.pop()
    return ".".join(parts)


def _display_path(path: Path, root: Path) -> str:
    if root.is_file():
        return path.name
    return path.relative_to(root).as_posix()


def _scan_python_files(root: Path, scan_errors: list[dict[str, Any]]) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix.casefold() == ".py" else []

    paths: list[Path] = []

    def record_walk_error(error: OSError) -> None:
        scan_errors.append(
            {
                "file": str(getattr(error, "filename", root)),
                "error_type": type(error).__name__,
                "message": str(error),
                "line": None,
                "offset": None,
            }
        )

    for directory, directory_names, file_names in os.walk(
        root, topdown=True, onerror=record_walk_error, followlinks=False
    ):
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name.casefold() not in _IGNORED_DIRECTORY_NAMES_CASEFOLDED
        )
        for file_name in sorted(file_names):
            if Path(file_name).suffix.casefold() == ".py":
                paths.append(Path(directory) / file_name)
    return paths


def _dependencies(tree: ast.AST) -> set[str]:
    dependencies: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            dependencies.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = "." * node.level
            if node.module:
                dependencies.add(f"{prefix}{node.module}")
            else:
                dependencies.update(f"{prefix}{alias.name}" for alias in node.names)
    return dependencies


def _parse_error(file_path: str, error: Exception) -> dict[str, Any]:
    return {
        "file": file_path,
        "error_type": type(error).__name__,
        "message": str(error),
        "line": getattr(error, "lineno", None),
        "offset": getattr(error, "offset", None),
    }


def _import_entries(tree: ast.AST) -> list[dict[str, Any]]:
    """Collect import statements with source locations.

    Each alias becomes one entry so callers can attribute lines/columns to a
    single bound name.  ``module`` is the imported module as written (without
    relative dots); relative imports are described by ``level``.
    """
    entries: list[dict[str, Any]] = []

    def add(
        *,
        is_from: bool,
        level: int,
        module: str | None,
        name: str,
        asname: str | None,
        line: int | None,
        column: int | None,
    ) -> None:
        entries.append(
            {
                "name": name,
                "asname": asname,
                "module": module or "",
                "level": level,
                "is_from": is_from,
                "is_relative": level > 0,
                "line": line,
                "column": column,
            }
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(
                    is_from=False,
                    level=0,
                    module=alias.name,
                    name=alias.name,
                    asname=alias.asname,
                    line=node.lineno,
                    column=node.col_offset,
                )
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                add(
                    is_from=True,
                    level=node.level,
                    module=node.module,
                    name=alias.name,
                    asname=alias.asname,
                    line=node.lineno,
                    column=node.col_offset,
                )
    return entries


@dataclass(frozen=True, slots=True)
class PythonFileParse:
    """Result of parsing a single Python source file.

    Exactly one of ``symbols`` (with ``parsed=True``) or ``error`` is
    populated.  The dataclass lets both ``PythonSourceParser`` (whole project)
    and the V0.3 ``SourceProjectParser`` reuse one per-file implementation.
    """

    displayed_path: str
    module: str = ""
    symbols: list[dict[str, Any]] = field(default_factory=list)
    dependencies: set[str] = field(default_factory=set)
    imports: list[dict[str, Any]] = field(default_factory=list)
    call_graph: dict[str, set[str]] = field(default_factory=dict)
    entry_point: int | None = None
    error: dict[str, Any] | None = None
    parsed: bool = False


def parse_python_file(path: Path, displayed_path: str) -> PythonFileParse:
    """Read and parse one Python file without executing it.

    ``displayed_path`` is the project-relative path used for module naming,
    error reporting and symbol ``file`` values.  Read/encoding/syntax errors
    are returned as ``PythonFileParse.error`` instead of being raised, so a
    single broken file never aborts a whole project scan.
    """
    try:
        with tokenize.open(path) as source_file:
            source = source_file.read()
        tree = ast.parse(source, filename=displayed_path)
    except (OSError, SyntaxError, UnicodeError) as error:
        return PythonFileParse(
            displayed_path=displayed_path,
            error=_parse_error(displayed_path, error),
        )

    module = _module_name(Path(displayed_path))
    visitor = _SymbolVisitor(module, displayed_path)
    visitor.visit(tree)
    return PythonFileParse(
        displayed_path=displayed_path,
        module=module,
        symbols=visitor.symbols,
        dependencies=_dependencies(tree),
        imports=_import_entries(tree),
        call_graph=visitor.call_graph,
        entry_point=_main_guard_line(tree),
        parsed=True,
    )


def _merge_call_graph(
    destination: dict[str, set[str]], source: dict[str, set[str]]
) -> None:
    for caller, callees in source.items():
        destination.setdefault(caller, set()).update(callees)


class PythonSourceParser:
    """Scan Python files and return symbols, imports and a resolved call graph."""

    async def analyze(self, request: ProjectInput) -> SourceAnalysisResult:
        """Analyze a project directory or one Python file without executing it."""
        root = Path(request.project_path).expanduser()
        parse_errors: list[dict[str, Any]] = []
        if not root.exists():
            parse_errors.append(
                {
                    "file": str(root),
                    "error_type": "PathNotFoundError",
                    "message": f"Project path does not exist: {root}",
                    "line": None,
                    "offset": None,
                }
            )
            return SourceAnalysisResult(
                task_id=request.task_id,
                target_id=request.target_id,
                project_path=request.project_path,
                metadata=self._metadata(
                    0,
                    0,
                    parse_errors,
                    imports={},
                    entry_points=[],
                    scanned=False,
                ),
            )

        root = root.resolve()
        python_files = _scan_python_files(root, parse_errors)
        symbols: list[dict[str, Any]] = []
        dependencies: set[str] = set()
        call_graph: dict[str, set[str]] = {}
        parsed_file_count = 0
        displayed_files = [_display_path(path, root) for path in python_files]
        parsed_files: list[PythonFileParse] = []

        for path, displayed_path in zip(python_files, displayed_files):
            parsed_file = parse_python_file(path, displayed_path)
            if parsed_file.error is not None:
                LOGGER.debug(
                    "Unable to parse %s: %s",
                    path,
                    parsed_file.error.get("message"),
                )
                parse_errors.append(parsed_file.error)
                continue

            parsed_file_count += 1
            parsed_files.append(parsed_file)
            symbols.extend(parsed_file.symbols)
            dependencies.update(parsed_file.dependencies)
            _merge_call_graph(call_graph, parsed_file.call_graph)

        symbols.sort(
            key=lambda symbol: (
                str(symbol["file"]),
                int(symbol["line"]),
                str(symbol["qualified_name"]),
            )
        )
        resolved_call_graph = resolve_call_graph_for_files(
            call_graph, symbols, parsed_files
        )
        return SourceAnalysisResult(
            task_id=request.task_id,
            target_id=request.target_id,
            project_path=request.project_path,
            languages=["Python"] if python_files else [],
            files=displayed_files,
            symbols=symbols,
            dependencies=sorted(dependencies),
            call_graph=resolved_call_graph,
            metadata=self._metadata(
                len(python_files),
                parsed_file_count,
                parse_errors,
                imports={file.displayed_path: file.imports for file in parsed_files},
                entry_points=_entry_points(parsed_files),
                scanned=True,
            ),
        )

    @staticmethod
    def _metadata(
        file_count: int,
        parsed_file_count: int,
        parse_errors: Iterable[dict[str, Any]],
        *,
        imports: dict[str, list[dict[str, Any]]],
        entry_points: list[dict[str, Any]],
        scanned: bool,
    ) -> dict[str, Any]:
        errors = list(parse_errors)
        return {
            "parser": "python_ast",
            "scanned": scanned,
            "file_count": file_count,
            "parsed_file_count": parsed_file_count,
            "imports": imports,
            "entry_points": entry_points,
            "error_count": len(errors),
            "parse_errors": errors,
            "ignored_directories": sorted(IGNORED_DIRECTORY_NAMES),
        }
