"""Business-logic locator consuming only :class:`BinaryAnalysisResult` facts.

This module never re-reads the target binary or invokes external tools.  It
converts the already-extracted strings, imports and function facts into
explainable logic-location clues (authentication, cryptography, registration).
Clues are features, not vulnerability findings, and never set a final status.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from typing import Any

from vulnagent.contracts import BinaryAnalysisResult

# category -> lowercased substring hints.
KEYWORD_HINTS: dict[str, tuple[str, ...]] = {
    "authentication": (
        "password", "passwd", "login", "logon", "credential", "username",
        "incorrect password", "access denied", "authentication", "authenticate",
        "verify password", "check password", "logonuser",
        "cryptverifysignature", "bcryptverifysignature",
    ),
    "cryptography": (
        "bcrypt", "cryptencrypt", "cryptdecrypt", "cryptography", "crypto",
        "aes", "rsa", "md5", "sha1", "sha256", "sha512", "hmac", "cipher",
        "encrypt", "decrypt", "evp_", "openssl", "rtlgenrandom", "ssl",
    ),
    "registration": (
        "license", "serial", "product key", "activation", "activate", "trial",
        "register", "registration", "expired", "expiry", "unlock", "validate",
    ),
    "network_input": (
        "recv", "recvfrom", "wsarecv", "socket", "accept", "internetreadfile",
        "winhttp", "curl_easy", "http request", "network input",
    ),
    "memory_operation": (
        "strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf", "memcpy",
        "memmove", "malloc", "calloc", "realloc", "free", "memory operation",
    ),
}

_SOURCE_CONFIDENCE = {
    "import": 0.75,
    "function": 0.85,
    "string": 0.5,
    "normalized_string": 0.55,
    "pseudocode": 0.7,
}
_MAX_ITEMS = 10_000
_MAX_NORMALIZED_STRINGS = 64
_HEX_TEXT = re.compile(r"^(?:[0-9a-fA-F]{2}){4,}$")
_BASE64_TEXT = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")


def _matched_categories(text: str) -> list[str]:
    """Return every category whose keyword hints appear in ``text`` (lowercased)."""
    lowered = text.lower()
    return [cat for cat, hints in KEYWORD_HINTS.items() if any(h in lowered for h in hints)]


class LogicAnalyzer:
    """Locate authentication, cryptography and registration logic clues.

    Implements the ``BinaryFeatureAnalyzer.inspect`` shape: consumes a
    :class:`BinaryAnalysisResult` and returns a JSON-friendly feature dict.
    """

    async def inspect(self, result: BinaryAnalysisResult) -> dict[str, Any]:
        locations: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        normalized_strings = _normalize_obfuscated_strings(result.strings)

        for text in result.strings[:_MAX_ITEMS]:
            for category in _matched_categories(str(text)):
                self._add(locations, seen, category, str(text), "string", None, None)

        for imp in result.imports[:_MAX_ITEMS]:
            for category in _matched_categories(str(imp)):
                self._add(locations, seen, category, str(imp), "import", None, None)

        for item in normalized_strings:
            decoded = item["decoded"]
            for category in _matched_categories(decoded):
                self._add(
                    locations,
                    seen,
                    category,
                    decoded,
                    "normalized_string",
                    None,
                    None,
                )

        for fn in self._functions(result.functions):
            name = str(fn.get("name", "") or "")
            address = fn.get("address")
            addr_text = hex(address) if isinstance(address, int) and not isinstance(address, bool) else None
            for category in _matched_categories(name):
                self._add(locations, seen, category, name, "function", addr_text, name or None)

        metadata = result.metadata if isinstance(result.metadata, Mapping) else {}
        reverse_tool = metadata.get("reverse_tool")
        pseudocode = reverse_tool.get("pseudocode") if isinstance(reverse_tool, Mapping) else None
        if isinstance(pseudocode, Mapping):
            for address, raw_code in list(pseudocode.items())[:_MAX_ITEMS]:
                code = str(raw_code)
                lowered = code.casefold()
                for category, hints in KEYWORD_HINTS.items():
                    matched_hint = next((hint for hint in hints if hint in lowered), None)
                    if matched_hint:
                        self._add(
                            locations,
                            seen,
                            category,
                            matched_hint,
                            "pseudocode",
                            str(address),
                            f"func@{address}",
                        )

        self._pin_to_pseudocode(result, locations)

        return {
            "target_id": result.target_id,
            "locations": locations,
            "summary": self._summarize(locations),
            "deobfuscation": {
                "engine": "bounded-string-normalizer",
                "target_executed": False,
                "decoded_count": len(normalized_strings),
                "items": normalized_strings,
                "limitations": [
                    "only printable Base64 and hexadecimal text are normalized",
                    "virtualized control flow and encrypted runtime strings are not reconstructed",
                ],
            },
        }

    @staticmethod
    def _functions(functions: Any) -> list[Mapping[str, Any]]:
        if not isinstance(functions, list):
            return []
        return [fn for fn in functions if isinstance(fn, Mapping)]

    @staticmethod
    def _add(
        locations: list[dict[str, Any]],
        seen: set[tuple[str, str, str]],
        category: str,
        text: str,
        source: str,
        address: str | None,
        function: str | None,
    ) -> None:
        key = (category, text[:128].lower(), source)
        if key in seen:
            return
        seen.add(key)
        locations.append({
            "category": category,
            "matched": text[:128],
            "source": source,
            "address": address,
            "function": function,
            "confidence": _SOURCE_CONFIDENCE[source],
        })

    def _pin_to_pseudocode(self, result: BinaryAnalysisResult, locations: list[dict[str, Any]]) -> None:
        """Best-effort: attach an address from radare2 pseudocode facts."""
        metadata = result.metadata if isinstance(result.metadata, Mapping) else {}
        tool = metadata.get("reverse_tool")
        pseudocode = tool.get("pseudocode") if isinstance(tool, Mapping) else None
        if not isinstance(pseudocode, Mapping):
            return
        for address, code in pseudocode.items():
            code_lower = str(code).lower()
            for loc in locations:
                if loc["address"] is None and loc["matched"].lower() in code_lower:
                    loc["address"] = address
                    loc["function"] = f"func@{address}"

    @staticmethod
    def _summarize(locations: list[dict[str, Any]]) -> dict[str, Any]:
        per: dict[str, dict[str, Any]] = {}
        for loc in locations:
            cat = per.setdefault(loc["category"], {"count": 0, "sources": set()})
            cat["count"] += 1
            cat["sources"].add(loc["source"])
        return {
            cat: {"count": data["count"], "sources": sorted(data["sources"])}
            for cat, data in sorted(per.items())
        }


def _normalize_obfuscated_strings(values: list[str]) -> list[dict[str, str]]:
    """Decode a bounded set of reversible text encodings without execution."""

    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw_value in values[:_MAX_ITEMS]:
        original = str(raw_value).strip()
        candidates: list[tuple[str, bytes]] = []
        if _HEX_TEXT.fullmatch(original):
            try:
                candidates.append(("hex", bytes.fromhex(original)))
            except ValueError:
                pass
        if _BASE64_TEXT.fullmatch(original) and len(original) % 4 == 0:
            try:
                candidates.append(("base64", base64.b64decode(original, validate=True)))
            except (binascii.Error, ValueError):
                pass
        for encoding, payload in candidates:
            try:
                decoded = payload.decode("utf-8")
            except UnicodeDecodeError:
                continue
            decoded = decoded.strip("\x00\r\n\t ")
            if len(decoded) < 4 or not _mostly_printable(decoded):
                continue
            key = (encoding, decoded.casefold())
            if key in seen or decoded == original:
                continue
            seen.add(key)
            normalized.append(
                {
                    "encoding": encoding,
                    "original": original[:256],
                    "decoded": decoded[:512],
                    "basis": "deterministic reversible text normalization",
                }
            )
            if len(normalized) >= _MAX_NORMALIZED_STRINGS:
                return normalized
    return normalized


def _mostly_printable(value: str) -> bool:
    printable = sum(character.isprintable() for character in value)
    return printable / max(1, len(value)) >= 0.9
