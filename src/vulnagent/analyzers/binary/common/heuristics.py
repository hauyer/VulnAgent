"""Bounded, explainable binary packing and obfuscation signal inspection."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vulnagent.contracts import BinaryAnalysisResult

_HIGH_ENTROPY = 7.2
_LOW_IMPORT_COUNT = 3
_KNOWN_PACKER_MARKERS = ("upx", "aspack", "themida", "vmprotect", "mpress", "petite")


def inspect_packing_signals(result: BinaryAnalysisResult) -> dict[str, Any]:
    """Return bounded, non-verdict packing/obfuscation signals from analysis facts.

    The function consumes only already-extracted result fields.  It neither reads the
    target nor invokes a tool, and it deliberately reports *signals* rather than a
    malware, packing, or obfuscation conclusion.
    """
    metadata = result.metadata if isinstance(result.metadata, Mapping) else {}
    raw_sections = metadata.get("sections", [])
    sections = raw_sections if isinstance(raw_sections, list) else []
    section_signals: list[dict[str, Any]] = []
    marker_sections: list[str] = []
    high_entropy_sections: list[str] = []

    for raw_section in sections[:4096]:
        if not isinstance(raw_section, Mapping):
            continue
        name = str(raw_section.get("name", ""))[:128]
        raw_entropy = raw_section.get("entropy")
        entropy_value = (
            round(float(raw_entropy), 6)
            if isinstance(raw_entropy, (int, float)) and not isinstance(raw_entropy, bool)
            else None
        )
        marker = next((item for item in _KNOWN_PACKER_MARKERS if item in name.lower()), None)
        high_entropy = entropy_value is not None and entropy_value >= _HIGH_ENTROPY
        if high_entropy:
            high_entropy_sections.append(name)
        if marker:
            marker_sections.append(name)
        section_signals.append(
            {
                "name": name,
                "entropy": entropy_value,
                "high_entropy": high_entropy,
                "packer_marker": marker,
            }
        )

    imports = [str(item)[:256] for item in result.imports[:10000]]
    entry_point = metadata.get("entry_point")
    entry_in_high_entropy_section = any(
        item["high_entropy"]
        and isinstance(entry_point, int)
        and _section_contains_address(sections, item["name"], entry_point)
        for item in section_signals
    )
    signals: list[str] = []
    if high_entropy_sections:
        signals.append("high_entropy_section")
    if marker_sections:
        signals.append("packer_section_name")
    if len(imports) <= _LOW_IMPORT_COUNT:
        signals.append("low_import_count")
    if entry_in_high_entropy_section:
        signals.append("entry_point_in_high_entropy_section")

    # Score is intentionally capped and only ranks inspection priority, not truth.
    score = min(
        100,
        20 * bool(high_entropy_sections)
        + 45 * bool(marker_sections)
        + 15 * (len(imports) <= _LOW_IMPORT_COUNT)
        + 20 * bool(entry_in_high_entropy_section),
    )
    return {
        "inspector": "bounded-packing-signals",
        "version": 1,
        "signal_score": score,
        "signals": signals,
        "section_signals": section_signals,
        "import_count": len(imports),
        "entry_point_in_high_entropy_section": entry_in_high_entropy_section,
        "limitations": [
            "heuristic signals are not a packing or obfuscation verdict",
            "only parser-provided section and import facts are considered",
        ],
    }


def _section_contains_address(
    sections: list[Any], name: str, address: int
) -> bool:
    """Check a parser section record without trusting its numeric fields."""
    for section in sections:
        if not isinstance(section, Mapping) or str(section.get("name", "")) != name:
            continue
        start = section.get("address")
        size = section.get("virtual_size", section.get("size"))
        if (
            isinstance(start, int)
            and isinstance(size, int)
            and not isinstance(start, bool)
            and not isinstance(size, bool)
            and size > 0
        ):
            return start <= address < start + size
    return False
