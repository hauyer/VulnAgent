"""Project-level source parser for the V0.3 first real source chain.

``SourceProjectParser`` implements the public ``SourceParser`` protocol from
``vulnagent.contracts``.  Given a ``ProjectInput`` pointing at a directory or
a single source file it:

1. walks the project with conservative ignore rules and resource limits;
2. recognizes the languages present (see ``languages.py``);
3. structurally parses the supported languages (Python today) and keeps the
   remaining recognised files indexed without pretending they were parsed;
4. returns one standard ``SourceAnalysisResult`` aggregating files, symbols,
   dependencies, a basic call graph and rich ``metadata`` (per-language
   counts, unsupported languages, parse errors, scan limits).

The parser never judges vulnerabilities and never executes code.  A project
that mixes supported and unsupported languages still reports its real
language set, so downstream Audit can distinguish an *empty* project from a
*recognised-but-not-yet-parsed* one.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnagent.contracts import ProjectInput, SourceAnalysisResult

from .languages import (
    DEFAULT_MAX_FILE_BYTES,
    IGNORED_DIRECTORY_NAMES,
    detect_language,
    is_ignored_directory,
    recognized_languages,
)
from .python_parser import parse_python_file

LOGGER = logging.getLogger(__name__)

#: Languages whose structure is parsed into symbols in V0.3 (only Python).
SUPPORTED_LANGUAGES: frozenset[str] = frozenset(
    spec.identifier
    for spec in recognized_languages()
    if spec.structurally_parsed
)


@dataclass(frozen=True, slots=True)
class _SourceFile:
    """One recognised source file discovered during the project walk."""

    real_path: Path
    displayed_path: str
    language: str
    structurally_parsed: bool


class SourceProjectParser:
    """Scan a source directory and produce a standard SourceAnalysisResult."""

    async def analyze(self, request: ProjectInput) -> SourceAnalysisResult:
        """Analyze ``request.project_path`` (directory or single file)."""
        root = Path(request.project_path).expanduser()
        if not root.exists():
            return self._missing_result(request, root)

        resolved_root = root.resolve()
        max_file_bytes = self._max_file_bytes(request)
        files, other_count, skipped, walk_errors = self._scan(
            resolved_root, max_file_bytes
        )
        return self._build_result(
            request=request,
            files=files,
            other_file_count=other_count,
            skipped_oversized=skipped,
            walk_errors=walk_errors,
            max_file_bytes=max_file_bytes,
        )

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def _scan(
        self,
        root: Path,
        max_file_bytes: int,
    ) -> tuple[list[_SourceFile], int, int, list[dict[str, Any]]]:
        """Walk the project, classify files, return recognised source files."""
        discovered: list[_SourceFile] = []
        other_file_count = 0
        skipped_oversized = 0
        walk_errors: list[dict[str, Any]] = []

        def record_walk_error(error: OSError) -> None:
            walk_errors.append(
                {
                    "file": str(getattr(error, "filename", root)),
                    "error_type": type(error).__name__,
                    "message": str(error),
                    "line": None,
                    "offset": None,
                }
            )

        def accept(path: Path) -> None:
            nonlocal other_file_count, skipped_oversized
            try:
                size = path.stat().st_size
            except OSError as error:  # pragma: no cover - defensive
                walk_errors.append(
                    {
                        "file": str(path),
                        "error_type": type(error).__name__,
                        "message": str(error),
                        "line": None,
                        "offset": None,
                    }
                )
                return

            if size > max_file_bytes:
                skipped_oversized += 1
                return

            spec = detect_language(path)
            if spec is None:
                other_file_count += 1
                return

            discovered.append(
                _SourceFile(
                    real_path=path,
                    displayed_path=self._display_path(path, root),
                    language=spec.identifier,
                    structurally_parsed=spec.structurally_parsed,
                )
            )

        if root.is_file():
            accept(root)
        else:
            for directory, directory_names, file_names in os.walk(
                root,
                topdown=True,
                onerror=record_walk_error,
                followlinks=False,
            ):
                directory_names[:] = sorted(
                    name
                    for name in directory_names
                    if not is_ignored_directory(name)
                )
                for file_name in sorted(file_names):
                    accept(Path(directory) / file_name)

        discovered.sort(key=lambda item: item.displayed_path)
        return discovered, other_file_count, skipped_oversized, walk_errors

    # ------------------------------------------------------------------
    # Result assembly
    # ------------------------------------------------------------------
    def _build_result(
        self,
        *,
        request: ProjectInput,
        files: list[_SourceFile],
        other_file_count: int,
        skipped_oversized: int,
        walk_errors: list[dict[str, Any]],
        max_file_bytes: int,
    ) -> SourceAnalysisResult:
        parse_errors = list(walk_errors)
        symbols: list[dict[str, Any]] = []
        dependencies: set[str] = set()
        call_graph: dict[str, set[str]] = {}
        parsed_file_count = 0

        counts: dict[str, int] = {}
        for source_file in files:
            counts[source_file.language] = (
                counts.get(source_file.language, 0) + 1
            )
            if not source_file.structurally_parsed:
                continue

            parsed = parse_python_file(
                source_file.real_path,
                source_file.displayed_path,
            )
            if parsed.error is not None:
                LOGGER.debug(
                    "Unable to parse %s: %s",
                    source_file.real_path,
                    parsed.error.get("message"),
                )
                parse_errors.append(parsed.error)
                continue

            parsed_file_count += 1
            symbols.extend(parsed.symbols)
            dependencies.update(parsed.dependencies)
            for caller, callees in parsed.call_graph.items():
                call_graph.setdefault(caller, set()).update(callees)

        symbols.sort(
            key=lambda symbol: (
                str(symbol["file"]),
                int(symbol["line"]),
                str(symbol["qualified_name"]),
            )
        )
        serialized_call_graph = {
            caller: sorted(callees)
            for caller, callees in sorted(call_graph.items())
        }

        languages = sorted(counts) if counts else []
        unsupported = sorted(
            identifier
            for identifier in counts
            if identifier not in SUPPORTED_LANGUAGES
        )
        parsed_languages = sorted(
            identifier
            for identifier in counts
            if identifier in SUPPORTED_LANGUAGES
        )

        return SourceAnalysisResult(
            task_id=request.task_id,
            target_id=request.target_id,
            project_path=request.project_path,
            languages=languages,
            files=[source_file.displayed_path for source_file in files],
            symbols=symbols,
            dependencies=sorted(dependencies),
            call_graph=serialized_call_graph,
            metadata={
                "parser": "source_project",
                "scanned": True,
                "file_count": len(files),
                "parsed_file_count": parsed_file_count,
                "language_counts": {
                    identifier: counts[identifier]
                    for identifier in sorted(counts)
                },
                "parsed_languages": parsed_languages,
                "unsupported_languages": unsupported,
                "other_file_count": other_file_count,
                "skipped_oversized_files": skipped_oversized,
                "max_file_bytes": max_file_bytes,
                "error_count": len(parse_errors),
                "parse_errors": parse_errors,
                "ignored_directories": sorted(IGNORED_DIRECTORY_NAMES),
            },
        )

    def _missing_result(
        self,
        request: ProjectInput,
        root: Path,
    ) -> SourceAnalysisResult:
        error = {
            "file": str(root),
            "error_type": "PathNotFoundError",
            "message": f"Project path does not exist: {root}",
            "line": None,
            "offset": None,
        }
        return SourceAnalysisResult(
            task_id=request.task_id,
            target_id=request.target_id,
            project_path=request.project_path,
            metadata={
                "parser": "source_project",
                "scanned": False,
                "file_count": 0,
                "parsed_file_count": 0,
                "language_counts": {},
                "parsed_languages": [],
                "unsupported_languages": [],
                "other_file_count": 0,
                "skipped_oversized_files": 0,
                "max_file_bytes": 0,
                "error_count": 1,
                "parse_errors": [error],
                "ignored_directories": sorted(IGNORED_DIRECTORY_NAMES),
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _display_path(path: Path, root: Path) -> str:
        """Project-relative POSIX path, or the bare name for a single file."""
        if root.is_file():
            return path.name
        return path.relative_to(root).as_posix()

    @staticmethod
    def _max_file_bytes(request: ProjectInput) -> int:
        raw = request.metadata.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = DEFAULT_MAX_FILE_BYTES
        if value <= 0:
            return DEFAULT_MAX_FILE_BYTES
        return value
