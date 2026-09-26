"""S3: on-demand, bounded context slicing for source auditing.

``ContextSliceProvider`` loads only the code fragments an analysis step
actually needs instead of whole files or whole trees:

* ``slice_symbol``      - the window around a symbol's definition line.
* ``slice_call_site``   - the window around a specific call site.
* ``slice_project``     - for a list of symbols, reads only the files that
  contain them and only the symbol/branch windows, never the whole file.

Every slice records its own facts (matched symbol, window bounds, source
kind) and the provider records its limits (max lines per file, max files,
max total bytes) plus which files were skipped or truncated, so a downstream
analysis result can honestly report what it saw and what it did not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_SYMBOL_DEF_RE = re.compile(
    r"^\s*(?:def|class|async\s+def|function|static\s+[\w\*]+\s+[\w]+)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:\(|\:|\{)"
)
_SYMBOL_USE_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*(?:\(|\s*=|\s*\.)")


@dataclass(frozen=True)
class ContextSlice:
    """One bounded fragment of a file with its provenance facts."""

    file_path: Path
    start_line: int  # 1-based
    end_line: int  # 1-based, inclusive
    text: str
    source_kind: str  # symbol_definition | call_site | branch_guard | user_request
    matched_symbol: str | None


@dataclass
class SliceResult:
    """Aggregate of bounded slices plus the facts/limits of the slice pass."""

    slices: list[ContextSlice] = field(default_factory=list)
    total_bytes: int = 0
    skipped_files: list[str] = field(default_factory=list)
    truncated_files: list[str] = field(default_factory=list)
    limits: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


class ContextSliceProvider:
    """Deterministic, bounded source slicing without whole-file loads."""

    def __init__(
        self,
        *,
        max_lines_per_file: int = 120,
        max_files: int = 8,
        max_total_bytes: int = 64 * 1024,
        window_before: int = 5,
        window_after: int = 15,
    ) -> None:
        if max_lines_per_file < 1 or max_files < 1 or max_total_bytes < 1:
            raise ValueError("slice limits must be positive")
        self.max_lines_per_file = max_lines_per_file
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.window_before = window_before
        self.window_after = window_after

    # ------------------------------------------------------------------
    # symbol windows
    # ------------------------------------------------------------------
    def slice_symbol(
        self, path: Path, symbol: str, *, source_kind: str = "symbol_definition"
    ) -> ContextSlice | None:
        """Return the bounded window around ``symbol``'s definition line.

        Only the file's lines are read as a window; the whole file is never
        materialized.  ``None`` means the symbol was not found (recorded as a
        limit fact by the caller).
        """
        lines = _read_lines_bounded(path, self.max_lines_per_file)
        if lines is None:
            return None
        definition_line = _find_definition_line(lines, symbol)
        if definition_line is None:
            return None
        start = max(1, definition_line - self.window_before)
        end = min(len(lines), definition_line + self.window_after)
        return ContextSlice(
            file_path=Path(path),
            start_line=start,
            end_line=end,
            text="\n".join(lines[start - 1 : end]),
            source_kind=source_kind,
            matched_symbol=symbol,
        )

    def slice_call_site(
        self, path: Path, symbol: str, call_line: int
    ) -> ContextSlice | None:
        """Return the bounded window around a known call site line."""
        lines = _read_lines_bounded(path, self.max_lines_per_file)
        if lines is None or call_line < 1 or call_line > len(lines):
            return None
        start = max(1, call_line - self.window_before)
        end = min(len(lines), call_line + self.window_after)
        return ContextSlice(
            file_path=Path(path),
            start_line=start,
            end_line=end,
            text="\n".join(lines[start - 1 : end]),
            source_kind="call_site",
            matched_symbol=symbol,
        )

    # ------------------------------------------------------------------
    # project-wide bounded slicing
    # ------------------------------------------------------------------
    def slice_project(
        self,
        root: Path,
        symbols: list[str],
        *,
        file_suffixes: tuple[str, ...] = (".py", ".c", ".cc", ".cpp", ".h", ".hpp", ".js"),
    ) -> SliceResult:
        """Slice only the files that contain any requested symbol.

        Files are scanned in deterministic order; hard limits (max files,
        max total bytes) stop the pass and the remaining files are recorded
        as skipped.  Only symbol windows are read, never whole files.
        """
        result = SliceResult(limits={
            "max_lines_per_file": self.max_lines_per_file,
            "max_files": self.max_files,
            "max_total_bytes": self.max_total_bytes,
        })
        root = Path(root)
        files = sorted(
            p
            for p in root.rglob("*")
            if p.is_file() and p.suffix.lower() in file_suffixes
        )
        if not files:
            result.notes.append("no source files matched the requested suffixes")
            return result

        for path in files:
            if len(result.slices) >= self.max_files:
                result.skipped_files.append(str(path))
                continue
            try:
                data = path.read_bytes()
            except OSError as exc:
                result.skipped_files.append(f"{path} (unreadable: {exc})")
                continue
            if result.total_bytes + len(data) > self.max_total_bytes:
                result.truncated_files.append(str(path))
                continue
            text = data.decode("utf-8", errors="replace")
            lines = text.splitlines()
            for symbol in symbols:
                if len(result.slices) >= self.max_files:
                    break
                line_no = _find_definition_line(lines, symbol)
                kind = "symbol_definition"
                if line_no is None:
                    line_no = _find_usage_line(lines, symbol)
                    kind = "user_request"
                if line_no is None:
                    continue
                start = max(1, line_no - self.window_before)
                end = min(len(lines), line_no + self.window_after)
                result.slices.append(
                    ContextSlice(
                        file_path=path,
                        start_line=start,
                        end_line=end,
                        text="\n".join(lines[start - 1 : end]),
                        source_kind=kind,
                        matched_symbol=symbol,
                    )
                )
                result.total_bytes += sum(
                    len(line.encode("utf-8", errors="replace"))
                    for line in lines[start - 1 : end]
                )
        result.notes.append(
            f"files scanned={len(files)} slices={len(result.slices)} "
            f"bytes={result.total_bytes}"
        )
        return result


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _read_lines_bounded(
    path: Path, max_lines: int
) -> list[str] | None:
    """Read at most ``max_lines`` lines from a file (bounded memory)."""
    if not Path(path).is_file():
        return None
    lines: list[str] = []
    try:
        with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
            for idx, line in enumerate(fh):
                if idx >= max_lines:
                    break
                lines.append(line.rstrip("\r\n"))
    except OSError:
        return None
    return lines


def _find_definition_line(lines: list[str], symbol: str) -> int | None:
    for idx, line in enumerate(lines):
        m = _SYMBOL_DEF_RE.search(line)
        if m and m.group("name") == symbol:
            return idx + 1
    return None


def _find_usage_line(lines: list[str], symbol: str) -> int | None:
    for idx, line in enumerate(lines):
        if re.search(rf"\b{re.escape(symbol)}\b", line):
            return idx + 1
    return None


__all__ = [
    "ContextSlice",
    "ContextSliceProvider",
    "SliceResult",
]
