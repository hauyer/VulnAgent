"""Canonical source language registry and file-scanning policy.

This module is owned by the Source Parser boundary (member 2).  It defines:

- the set of source languages VulnAgent can *recognize* by file extension;
- which of those languages are currently parsed into structural symbols
  (only Python for the V0.3 first real source chain);
- the default ignore rules and resource limits used while walking a
  project directory.

Values here intentionally live in the parser package and are *not* part of
the public ``vulnagent.contracts`` surface.  Language identifiers are stable
lower-case strings (``"python"``, ``"c"``, ``"cpp"`` ...) so that downstream
consumers (Source Audit, Report, Experiments) can rely on one spelling.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "LanguageSpec",
    "detect_language",
    "language_display_name",
    "recognized_languages",
]


@dataclass(frozen=True, slots=True)
class LanguageSpec:
    """One recognisable source language.

    ``structurally_parsed`` marks languages for which the parser currently
    extracts symbols/dependencies/call graph.  Recognized but unparsed
    languages are still reported (files + counts) so that consumers never
    mistake an unsupported project for an empty one.
    """

    identifier: str
    display_name: str
    extensions: frozenset[str]
    structurally_parsed: bool = False


# Languages are ordered by identifier for deterministic reports.
_LANGUAGE_SPECS: tuple[LanguageSpec, ...] = (
    LanguageSpec(
        identifier="c",
        display_name="C",
        extensions=frozenset({".c", ".h"}),
    ),
    LanguageSpec(
        identifier="cpp",
        display_name="C++",
        extensions=frozenset(
            {
                ".cc",
                ".cpp",
                ".cxx",
                ".c++",
                ".hh",
                ".hpp",
                ".hxx",
                ".inl",
            }
        ),
    ),
    LanguageSpec(
        identifier="csharp",
        display_name="C#",
        extensions=frozenset({".cs"}),
    ),
    LanguageSpec(
        identifier="go",
        display_name="Go",
        extensions=frozenset({".go"}),
    ),
    LanguageSpec(
        identifier="java",
        display_name="Java",
        extensions=frozenset({".java"}),
    ),
    LanguageSpec(
        identifier="javascript",
        display_name="JavaScript",
        extensions=frozenset({".js", ".jsx", ".mjs", ".cjs"}),
    ),
    LanguageSpec(
        identifier="kotlin",
        display_name="Kotlin",
        extensions=frozenset({".kt", ".kts"}),
    ),
    LanguageSpec(
        identifier="php",
        display_name="PHP",
        extensions=frozenset({".php", ".php3", ".php4", ".php5", ".phtml"}),
    ),
    LanguageSpec(
        identifier="python",
        display_name="Python",
        extensions=frozenset({".py", ".pyi"}),
        structurally_parsed=True,
    ),
    LanguageSpec(
        identifier="ruby",
        display_name="Ruby",
        extensions=frozenset({".rb", ".rake", ".gemspec"}),
    ),
    LanguageSpec(
        identifier="rust",
        display_name="Rust",
        extensions=frozenset({".rs"}),
    ),
    LanguageSpec(
        identifier="swift",
        display_name="Swift",
        extensions=frozenset({".swift"}),
    ),
    LanguageSpec(
        identifier="typescript",
        display_name="TypeScript",
        extensions=frozenset({".ts", ".tsx", ".mts", ".cts"}),
    ),
)

_BY_EXTENSION: dict[str, LanguageSpec] = {
    extension: spec
    for spec in _LANGUAGE_SPECS
    for extension in spec.extensions
}

# Directories that are never treated as project source, regardless of their
# contents.  The core set mirrors ``python_parser.IGNORED_DIRECTORY_NAMES``;
# the extended entries cover common dependency/build/tooling folders of the
# other recognised languages.
IGNORED_DIRECTORY_NAMES: frozenset[str] = frozenset(
    {
        # version control
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        # python environments / caches / build
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".eggs",
        "build",
        "dist",
        # node / frontend
        "node_modules",
        ".next",
        ".nuxt",
        ".svelte-kit",
        # java / jvm
        "target",
        ".gradle",
        # ide / editor / tooling
        ".idea",
        ".vscode",
        ".vs",
        ".cargo",
        "Pods",
        "vendor",
        "coverage",
        "htmlcov",
        ".coverage",
        "site-packages",
        ".cache",
    }
)

_IGNORED_DIRECTORY_NAMES_CASEFOLDED: frozenset[str] = frozenset(
    name.casefold() for name in IGNORED_DIRECTORY_NAMES
)

#: Source files larger than this are skipped (never read into memory).
DEFAULT_MAX_FILE_BYTES: int = 1_000_000


def recognized_languages() -> tuple[LanguageSpec, ...]:
    """Return the immutable registry of recognizable languages."""
    return _LANGUAGE_SPECS


def detect_language(path: str | Path) -> LanguageSpec | None:
    """Detect a recognized language from a file name/suffix.

    Detection is case-insensitive on the extension.  Files without a known
    source extension return ``None`` (they are *not* source, or at least not
    yet recognised).
    """
    suffix = Path(str(path)).suffix.casefold()
    return _BY_EXTENSION.get(suffix)


def language_display_name(identifier: str) -> str:
    """Human-readable name for a canonical identifier (``"python"`` -> ``"Python"``)."""
    for spec in _LANGUAGE_SPECS:
        if spec.identifier == identifier:
            return spec.display_name
    return identifier


def is_ignored_directory(name: str) -> bool:
    """Whether a directory name should be skipped during a project walk."""
    return name.casefold() in _IGNORED_DIRECTORY_NAMES_CASEFOLDED
