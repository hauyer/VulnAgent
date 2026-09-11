"""Obfuscation feature analyzer consuming only :class:`BinaryAnalysisResult` facts.

It builds on the basic ``metadata["packing_signals"]`` produced by the
binary-reverse boundary when present, and adds deeper, still non-verdict
signals: anti-debugging imports, packer/protector marker strings and
string-obfuscation evidence.  It never re-reads the target or invokes a tool.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from math import log2
from typing import Any

from vulnagent.contracts import BinaryAnalysisResult

_ANTI_DEBUG_HINTS = (
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "outputdebugstring", "gettickcount", "rdtsc", "queryperformancecounter",
    "isdebugged", "debugactiveprocess",
)
_PACKER_MARKERS = (
    "upx", "themida", "vmprotect", "aspack", "mpress", "petite", ".vmp",
    "enigma", "obsidium", "winlicense",
)
_BASE64_LIKE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
_HIGH_STRING_ENTROPY = 4.5
_MAX_ITEMS = 10_000


def shannon_entropy(text: str) -> float:
    """Return Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((count / total) * log2(count / total) for count in counts.values())


class ObfuscationAnalyzer:
    """Report packing/obfuscation signals without issuing a verdict.

    Implements the ``BinaryFeatureAnalyzer.inspect`` shape: consumes a
    :class:`BinaryAnalysisResult` and returns a JSON-friendly feature dict.
    """

    async def inspect(self, result: BinaryAnalysisResult) -> dict[str, Any]:
        metadata = result.metadata if isinstance(result.metadata, Mapping) else {}
        base = metadata.get("packing_signals")
        base_score = 0
        base_signals: list[str] = []
        if isinstance(base, Mapping):
            base_signals = list(base.get("signals", []))
            try:
                base_score = min(100, int(base.get("signal_score", 0)))
            except (TypeError, ValueError):
                base_score = 0

        signals: list[dict[str, Any]] = []

        evidence = self._match_hints(result.imports, _ANTI_DEBUG_HINTS)
        if evidence:
            signals.append({"name": "anti_debug_import", "score": 20, "evidence": evidence})

        evidence = self._match_packer_hints(result.strings)
        if evidence:
            signals.append({"name": "packer_marker_string", "score": 25, "evidence": evidence})

        obfuscated = [
            s for s in result.strings[:_MAX_ITEMS]
            if _BASE64_LIKE.match(str(s).strip())
            or (len(str(s)) >= 16 and shannon_entropy(str(s)) >= _HIGH_STRING_ENTROPY)
        ]
        if obfuscated:
            ratio = round(len(obfuscated) / max(1, len(result.strings)), 3)
            signals.append({
                "name": "string_obfuscation",
                "score": 20 if ratio >= 0.3 else 10,
                "ratio": ratio,
                "evidence": obfuscated[:8],
            })

        score = min(100, base_score + sum(int(s["score"]) for s in signals))
        return {
            "target_id": result.target_id,
            "score": score,
            "base_score": base_score,
            "base_signals": base_signals,
            "signals": signals,
            "limitations": [
                "heuristic signals are not an obfuscation or packing verdict",
                "only already-extracted string, import and metadata facts are considered",
            ],
        }

    @staticmethod
    def _match_hints(values: list[str], hints: tuple[str, ...]) -> list[str]:
        matches: list[str] = []
        for value in values[:_MAX_ITEMS]:
            lowered = str(value).lower()
            if any(hint in lowered for hint in hints):
                matches.append(str(value)[:128])
        return matches[:8]

    @staticmethod
    def _match_packer_hints(values: list[str]) -> list[str]:
        """Match named protectors without substring false positives.

        In particular, ``mpress`` must not match ordinary .NET identifiers such
        as ``CompressionMode``.  UPX section names and VMProtect SDK markers use
        well-known suffixes, so those two names receive narrow suffix handling.
        """

        matches: list[str] = []
        for value in values[:_MAX_ITEMS]:
            lowered = str(value).lower()
            found = False
            for marker in _PACKER_MARKERS:
                if marker == ".vmp":
                    found = marker in lowered
                elif marker == "upx":
                    found = re.search(
                        r"(?<![a-z0-9])upx(?:[0-9!])?(?![a-z0-9])", lowered
                    ) is not None
                elif marker == "vmprotect":
                    found = re.search(
                        r"(?<![a-z0-9])vmprotect(?:begin|end)?(?![a-z0-9])",
                        lowered,
                    ) is not None
                else:
                    found = re.search(
                        rf"(?<![a-z0-9]){re.escape(marker)}(?![a-z0-9])",
                        lowered,
                    ) is not None
                if found:
                    break
            if found:
                matches.append(str(value)[:128])
        return matches[:8]
