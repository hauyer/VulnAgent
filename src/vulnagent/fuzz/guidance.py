"""Deterministic, non-exploit mutation guidance derived from static findings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


_MAX_INPUT_BYTES = 4096
_MAX_HINTS = 16


@dataclass(frozen=True, slots=True)
class MutationCase:
    """One generated input and its explainable strategy label."""

    data: bytes
    strategy: str
    risk_type: str | None = None


class RiskGuidedMutationPlanner:
    """Turn normalized risk types into bounded, inert boundary probes.

    The dictionary deliberately contains project markers and parser boundary
    characters, not shell commands, SQL statements, or exploit payloads.  Its
    purpose is to connect static attack-surface hypotheses to deterministic
    dynamic exploration while remaining suitable for a course sandbox.
    """

    _TOKENS: dict[str, tuple[bytes, ...]] = {
        "command_injection": (b"VULNAGENT_COMMAND_MARKER", b";", b"|"),
        "sql_injection": (b"VULNAGENT_SQL_MARKER", b"'", b'"'),
        "path_traversal": (b"VULNAGENT_PATH_MARKER", b"..", b"/"),
        "unsafe_deserialization": (
            b"VULNAGENT_DESERIALIZATION_MARKER",
            b"{",
            b"[",
        ),
        "dynamic_code_execution": (b"VULNAGENT_CODE_MARKER", b"(", b")"),
        "risky_binary_api": (b"VULNAGENT_BINARY_API_MARKER", b"%", b"\x00"),
        "fuzz_crash": (b"VULNAGENT_CRASH_RECHECK",),
    }
    _CWE_TYPES = {
        "CWE-22": "path_traversal",
        "CWE-78": "command_injection",
        "CWE-89": "sql_injection",
        "CWE-95": "dynamic_code_execution",
        "CWE-502": "unsafe_deserialization",
    }

    def generate(
        self,
        seed: bytes,
        hints: Sequence[Mapping[str, Any]],
        *,
        count: int,
    ) -> list[MutationCase]:
        """Generate at most ``count`` stable probes from structured hints."""
        if count <= 0:
            return []

        normalized = self.normalize_hints(hints)
        token_stream: list[tuple[str, bytes]] = []
        for risk_type in normalized:
            token_stream.extend(
                (risk_type, token) for token in self._TOKENS.get(risk_type, ())
            )
        if not token_stream:
            return []

        cases: list[MutationCase] = []
        seen: set[bytes] = set()
        modes = ("replace", "suffix", "prefix")
        round_index = 0
        while len(cases) < count and round_index < count * len(modes) * 2:
            risk_type, token = token_stream[round_index % len(token_stream)]
            mode = modes[(round_index // len(token_stream)) % len(modes)]
            if mode == "suffix":
                data = seed + token
            elif mode == "prefix":
                data = token + seed
            else:
                data = token
            data = data[:_MAX_INPUT_BYTES]
            if data not in seen:
                seen.add(data)
                cases.append(
                    MutationCase(
                        data=data,
                        strategy=f"risk_guided:{mode}",
                        risk_type=risk_type,
                    )
                )
            round_index += 1
        return cases

    @classmethod
    def normalize_hints(
        cls,
        hints: Sequence[Mapping[str, Any]],
    ) -> tuple[str, ...]:
        """Return a bounded, deduplicated list of supported risk types."""
        normalized: list[str] = []
        for hint in list(hints)[:_MAX_HINTS]:
            raw_type = hint.get("vulnerability_type")
            risk_type = str(raw_type).strip().casefold() if raw_type else ""
            if risk_type not in cls._TOKENS:
                cwe = str(hint.get("cwe_id") or "").strip().upper()
                risk_type = cls._CWE_TYPES.get(cwe, "")
            if risk_type and risk_type not in normalized:
                normalized.append(risk_type)
        return tuple(normalized)


__all__ = ["MutationCase", "RiskGuidedMutationPlanner"]
