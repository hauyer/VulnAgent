"""Explainable multi-signal classification for authorized protected programs.

The classifier is deliberately evidence based.  A manifest label may be shown
next to the result, but it never contributes to the observed confidence score.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from vulnagent.contracts import BinaryAnalysisResult


class ProtectionLevel(IntEnum):
    """Teaching-oriented protection strength rather than a malware verdict."""

    NONE = 0
    COMPRESSION = 1
    ENCRYPTION = 2
    LIGHT_VIRTUALIZATION = 3


@dataclass(frozen=True, slots=True)
class ProtectionProfile:
    code: str
    family: str
    level: ProtectionLevel
    section_markers: tuple[str, ...] = ()
    text_markers: tuple[str, ...] = ()


PROTECTION_PROFILES: tuple[ProtectionProfile, ...] = (
    ProtectionProfile("upx", "UPX", ProtectionLevel.COMPRESSION, ("upx0", "upx1", "upx!"), ("upx",)),
    ProtectionProfile("aspack", "ASPack", ProtectionLevel.COMPRESSION, (".aspack", ".adata"), ("aspack",)),
    ProtectionProfile("fsg", "FSG", ProtectionLevel.COMPRESSION, ("fsg!", ".fsg"), ("fsg",)),
    ProtectionProfile("pecompact", "PECompact", ProtectionLevel.ENCRYPTION, ("pec1", "pec2", ".pec"), ("pecompact",)),
    ProtectionProfile("upack", "Upack", ProtectionLevel.ENCRYPTION, ("upack", ".upack"), ("upack",)),
    ProtectionProfile("nsis", "NSIS", ProtectionLevel.ENCRYPTION, (".ndata",), ("nullsoft", "nsis error",)),
    ProtectionProfile("vmprotect_demo", "VMProtect demo", ProtectionLevel.LIGHT_VIRTUALIZATION, (".vmp0", ".vmp1", ".vmp2"), ("vmprotect", "vmpbegin", "vmpend")),
    ProtectionProfile("teaching_vm", "Teaching VM", ProtectionLevel.LIGHT_VIRTUALIZATION, (".vcode", ".vmdata", ".vdispatch"), ("vulnagent teaching vm", "vm_dispatch")),
)


def classify_protection(result: BinaryAnalysisResult) -> dict[str, Any]:
    """Classify eight supported PE protection families from independent facts.

    Section names, extracted strings, import sparsity, entry placement and
    entropy are scored independently.  The output contains the complete basis
    so an agent or examiner can reproduce the decision.
    """

    metadata = result.metadata if isinstance(result.metadata, Mapping) else {}
    sections = [item for item in metadata.get("sections", []) if isinstance(item, Mapping)]
    section_names = [str(item.get("name", "")).casefold() for item in sections[:4096]]
    strings = [str(item).casefold() for item in result.strings[:10_000]]
    high_entropy = [
        str(item.get("name", ""))
        for item in sections
        if isinstance(item.get("entropy"), (int, float)) and float(item["entropy"]) >= 7.2
    ]
    entry_point = metadata.get("entry_point")
    entry_high_entropy = any(
        _contains(item, entry_point) and str(item.get("name", "")) in high_entropy
        for item in sections
    )

    candidates: list[dict[str, Any]] = []
    format_details = metadata.get("format_details")
    dex_hints = (
        format_details.get("protection_hints", [])
        if isinstance(format_details, Mapping)
        else []
    )
    if result.file_format in {"DEX", "APK"} and isinstance(dex_hints, list) and dex_hints:
        for hint in dex_hints:
            candidates.append({
                "code": str(hint),
                "family": str(hint).upper(),
                "level": int(ProtectionLevel.ENCRYPTION),
                "level_name": ProtectionLevel.ENCRYPTION.name.casefold(),
                "confidence": 0.8,
                "evidence": {
                    "dex_runtime_marker": str(hint),
                    "container": result.file_format,
                },
            })
    for profile in PROTECTION_PROFILES:
        matched_sections = sorted({
            name for name in section_names
            if any(marker in name for marker in profile.section_markers)
        })
        matched_text = sorted({
            marker for marker in profile.text_markers
            if any(marker in value for value in strings)
        })
        score = min(
            100,
            55 * bool(matched_sections)
            + 30 * bool(matched_text)
            + 8 * (len(result.imports) <= 3)
            + 5 * bool(high_entropy)
            + 2 * entry_high_entropy,
        )
        if matched_sections or matched_text:
            candidates.append({
                "code": profile.code,
                "family": profile.family,
                "level": int(profile.level),
                "level_name": profile.level.name.casefold(),
                "confidence": round(score / 100, 2),
                "evidence": {
                    "section_markers": matched_sections,
                    "text_markers": matched_text,
                    "low_import_count": len(result.imports) <= 3,
                    "high_entropy_sections": high_entropy[:16],
                    "entry_point_in_high_entropy_section": entry_high_entropy,
                },
            })

    candidates.sort(key=lambda item: (-item["confidence"], -item["level"], item["code"]))
    selected = candidates[0] if candidates else None
    heuristic_score = min(
        45,
        15 * (len(result.imports) <= 3)
        + 15 * bool(high_entropy)
        + 15 * entry_high_entropy,
    )
    if selected is None and heuristic_score:
        selected = {
            "code": "unknown_protector",
            "family": "Unknown protector",
            "level": int(ProtectionLevel.ENCRYPTION if heuristic_score >= 30 else ProtectionLevel.COMPRESSION),
            "level_name": "encryption" if heuristic_score >= 30 else "compression",
            "confidence": round(heuristic_score / 100, 2),
            "evidence": {
                "section_markers": [],
                "text_markers": [],
                "low_import_count": len(result.imports) <= 3,
                "high_entropy_sections": high_entropy[:16],
                "entry_point_in_high_entropy_section": entry_high_entropy,
            },
        }
        candidates.append(selected)

    return {
        "schema_version": 1,
        "classifier": "multi-signal-protection-classifier",
        "supported_families": [profile.family for profile in PROTECTION_PROFILES],
        "selected": selected,
        "candidates": candidates,
        "declared_protection": metadata.get("declared_protection"),
        "declaration_used_for_scoring": False,
        "strategy": _strategy(selected),
        "limitations": [
            "classification is probabilistic and evidence must be reviewed",
            "commercial protectors outside the teaching matrix are reported as unknown",
        ],
    }


def _strategy(selected: Mapping[str, Any] | None) -> list[str]:
    if selected is None:
        return ["structural_parse", "static_decompile", "parseability_validation"]
    code = str(selected.get("code", ""))
    level = int(selected.get("level", 0) or 0)
    if code == "upx":
        return ["static_unpack_copy", "parseability_validation", "static_decompile"]
    if level == ProtectionLevel.COMPRESSION:
        return ["static_unpack_adapter", "parseability_validation", "sandbox_snapshot_fallback"]
    if level == ProtectionLevel.ENCRYPTION:
        return ["sandbox_snapshot", "import_trace_rebuild", "pe_structure_rebuild", "parseability_validation"]
    return ["sandbox_trace", "oep_candidate_scoring", "memory_snapshot", "semantic_deobfuscation", "parseability_validation"]


def _contains(section: Mapping[str, Any], address: Any) -> bool:
    start = section.get("address")
    size = section.get("virtual_size", section.get("size"))
    return (
        isinstance(address, int)
        and isinstance(start, int)
        and isinstance(size, int)
        and size > 0
        and start <= address < start + size
    )
