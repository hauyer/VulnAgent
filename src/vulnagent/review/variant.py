"""Known-pattern guided variant hypotheses (L7, roadmap §2.1).

A ``VariantHypothesis`` captures an *abstract* error pattern/invariant — never
a CVE ID, patch hint or target-specific label — plus candidate sites found in
the target's own source.  The track is ``guided_variant_search`` and its
results are excluded from the no-preset-positive blind score.  The generator
is deterministic and side-effect free; an LLM is never needed to emit a
hypothesis, and model output is only ever a suggestion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
import re


class VariantPatternKind(StrEnum):
    MISSING_NULL_CHECK = "missing_null_check"
    UNBOUNDED_COPY = "unbounded_copy_without_nul"
    INDEX_ARITHMETIC_OVERFLOW = "index_arithmetic_overflow"
    UNBOUNDED_FIELD_PARSE = "unbounded_fixed_width_field_parse"


@dataclass(frozen=True, slots=True)
class VariantHypothesis:
    hypothesis_id: str
    track: str = "guided_variant_search"
    pattern_kind: VariantPatternKind = VariantPatternKind.MISSING_NULL_CHECK
    invariant: str = ""
    candidate_sites: tuple[str, ...] = ()
    based_on_known_pattern: bool = True
    note: str = ""

    def digest(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id,
            "track": self.track,
            "pattern_kind": self.pattern_kind.value,
            "invariant": self.invariant,
            "candidate_sites": list(self.candidate_sites),
            "based_on_known_pattern": self.based_on_known_pattern,
            "note": self.note,
        }


_PATTERN_LIBRARY: dict[VariantPatternKind, str] = {
    VariantPatternKind.MISSING_NULL_CHECK: (
        "A function receives a pointer that may be NULL (e.g. a failed lookup) "
        "and dereferences it before validating; invariant: validate before use."
    ),
    VariantPatternKind.UNBOUNDED_COPY: (
        "A fixed-width source field is copied without explicit NUL termination; "
        "invariant: every copied buffer ends NUL-terminated within bounds."
    ),
    VariantPatternKind.INDEX_ARITHMETIC_OVERFLOW: (
        "An index is derived by arithmetic on untrusted sizes; invariant: all "
        "indices lie within the allocated range before access."
    ),
    VariantPatternKind.UNBOUNDED_FIELD_PARSE: (
        "A parser reads fixed-width fields with a bounded scan but unbounded "
        "write; invariant: parsed length never exceeds destination capacity."
    ),
}


def describe_pattern(kind: VariantPatternKind) -> str:
    return _PATTERN_LIBRARY[kind]


_SITE_RULES: dict[VariantPatternKind, tuple[str, ...]] = {
    VariantPatternKind.MISSING_NULL_CHECK: ("malloc", "calloc", "realloc", "lookup", "find"),
    VariantPatternKind.UNBOUNDED_COPY: ("strcpy", "strcat", "sprintf"),
    VariantPatternKind.INDEX_ARITHMETIC_OVERFLOW: ("strlen", "size", "offset"),
    VariantPatternKind.UNBOUNDED_FIELD_PARSE: ("sscanf", "fscanf", "scanf", "memcpy"),
}


class VariantHypothesisBuilder:
    """Deterministic source-site scan producing abstract hypotheses."""

    def __init__(self, source_roots: list[Path] | None = None) -> None:
        self.source_roots = source_roots or []

    def build(self, target_root: Path) -> list[VariantHypothesis]:
        """Scan ``target_root`` source files for pattern-relevant sites."""
        hypotheses: list[VariantHypothesis] = []
        for kind in VariantPatternKind:
            sites = self._find_sites(target_root, _SITE_RULES[kind])
            if not sites:
                continue
            hypotheses.append(
                VariantHypothesis(
                    hypothesis_id=f"vh-{kind.value}",
                    pattern_kind=kind,
                    invariant=describe_pattern(kind),
                    candidate_sites=tuple(sites[:10]),
                    note=(
                        "抽象错误模式引导；不含 CVE/补丁标签，"
                        "此 track 不并入盲态分数"
                    ),
                )
            )
        return hypotheses

    @staticmethod
    def _find_sites(target_root: Path, tokens: tuple[str, ...]) -> list[str]:
        sites: list[str] = []
        pattern = re.compile(r"\b(" + "|".join(re.escape(t) for t in tokens) + r")\b")
        files = []
        if target_root.is_dir():
            files = [
                p
                for p in target_root.rglob("*")
                if p.is_file()
                and p.suffix.lower() in {".c", ".cc", ".cpp", ".h", ".py", ".js"}
                and "third_party" not in str(p).replace("\\", "/").split("/")
            ]
        for path in files[:200]:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    sites.append(f"{path.name}:{line_no}")
        return sites
