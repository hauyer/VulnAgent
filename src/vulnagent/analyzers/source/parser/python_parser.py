"""Python project structure parser backed by the standard-library AST."""

from __future__ import annotations

import ast
import logging
import os
import tokenize
from pathlib import Path
from typing import Any, Iterable

from vulnagent.contracts import ProjectInput, SourceAnalysisResult

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
        self.symbols.append(self._symbol(node, kind="class"))
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


def _merge_call_graph(
    destination: dict[str, set[str]], source: dict[str, set[str]]
) -> None:
    for caller, callees in source.items():
        destination.setdefault(caller, set()).update(callees)


class PythonSourceParser:
    """Scan Python files and return symbols, imports, and a basic call graph."""

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
                metadata=self._metadata(0, 0, parse_errors, scanned=False),
            )

        root = root.resolve()
        python_files = _scan_python_files(root, parse_errors)
        symbols: list[dict[str, Any]] = []
        dependencies: set[str] = set()
        call_graph: dict[str, set[str]] = {}
        parsed_file_count = 0
        displayed_files = [_display_path(path, root) for path in python_files]

        for path, displayed_path in zip(python_files, displayed_files):
            try:
                with tokenize.open(path) as source_file:
                    source = source_file.read()
                tree = ast.parse(source, filename=displayed_path)
            except (OSError, SyntaxError, UnicodeError) as error:
                LOGGER.debug("Unable to parse %s: %s", path, error)
                parse_errors.append(_parse_error(displayed_path, error))
                continue

            parsed_file_count += 1
            relative_path = Path(displayed_path)
            visitor = _SymbolVisitor(_module_name(relative_path), displayed_path)
            visitor.visit(tree)
            symbols.extend(visitor.symbols)
            dependencies.update(_dependencies(tree))
            _merge_call_graph(call_graph, visitor.call_graph)

        symbols.sort(
            key=lambda symbol: (
                str(symbol["file"]),
                int(symbol["line"]),
                str(symbol["qualified_name"]),
            )
        )
        serialized_call_graph = {
            caller: sorted(callees) for caller, callees in sorted(call_graph.items())
        }
        return SourceAnalysisResult(
            task_id=request.task_id,
            target_id=request.target_id,
            project_path=request.project_path,
            languages=["Python"] if python_files else [],
            files=displayed_files,
            symbols=symbols,
            dependencies=sorted(dependencies),
            call_graph=serialized_call_graph,
            metadata=self._metadata(
                len(python_files), parsed_file_count, parse_errors, scanned=True
            ),
        )

    @staticmethod
    def _metadata(
        file_count: int,
        parsed_file_count: int,
        parse_errors: Iterable[dict[str, Any]],
        *,
        scanned: bool,
    ) -> dict[str, Any]:
        errors = list(parse_errors)
        return {
            "parser": "python_ast",
            "scanned": scanned,
            "file_count": file_count,
            "parsed_file_count": parsed_file_count,
            "error_count": len(errors),
            "parse_errors": errors,
            "ignored_directories": sorted(IGNORED_DIRECTORY_NAMES),
        }
