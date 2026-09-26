"""Untrusted-content boundary for anything that enters a prompt (L10).

Target source code, binary strings, tool stderr and web excerpts are all
untrusted data.  ``UntrustedExcerpt`` marks provenance (source URI / target
hash), enforces a maximum length, redacts sensitive fields and renders a
prompt fragment with an explicit source tag.  The LLM output is only ever a
suggestion (``PlanDecision`` / ``MODEL_REASONING_SUMMARY``); a regex check
here is an *additional* detector, never the permission boundary — tool calls
must still pass the ToolRegistry allowlist and authorization checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

_SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"https?://[^\s\"']+", re.IGNORECASE),          # URLs
    re.compile(r"[A-Za-z]:[\\/][^\s\"']+"),                    # windows paths
    re.compile(r"/(?:etc|home|usr|var|tmp|root)/[^\s\"']*"),   # unix paths
    re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"),  # IPv4
    re.compile(r"(?i)\b(api[_-]?key|key|secret|token|password|passwd)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

# Additional (non-authoritative) prompt-injection indicators.
_INJECTION_HINTS: tuple[re.Pattern[str], ...] = (
    re.compile(r"```|`[^`]*`"),            # markdown/code fences
    re.compile(r"(?i)ignore (all |the )?(previous|above|prior) (instructions|prompt|context)"),
    re.compile(r"(?i)system\s*[:：]\s*you are"),
    re.compile(r"!\[[^\]]*\]\(|javascript:|onerror=|onload="),
)


@dataclass(frozen=True, slots=True)
class UntrustedExcerpt:
    """One bounded, provenance-tagged slice of untrusted content."""

    text: str
    kind: str = "content"  # source / strings / log / web / tool_stderr
    source_uri: str | None = None
    target_sha256: str | None = None
    start_offset: int | None = None
    end_offset: int | None = None
    max_length: int = 4000
    truncated: bool = False
    redacted_fields: tuple[str, ...] = ()

    @property
    def length(self) -> int:
        return len(self.text)

    def to_prompt_fragment(self) -> str:
        """Render with an explicit source tag; never strip provenance."""
        meta: list[str] = [f"kind={self.kind}"]
        if self.source_uri:
            meta.append(f"source={self.source_uri}")
        if self.target_sha256:
            meta.append(f"sha256={self.target_sha256[:12]}")
        if self.truncated:
            meta.append(f"truncated_at={self.max_length}")
        header = "<untrusted " + " ".join(meta) + ">"
        return f"{header}\n{self.text}\n</untrusted>"


def redact(text: str, sensitive_patterns: Iterable[re.Pattern[str]] | None = None) -> str:
    """Replace sensitive fields with ``[redacted]`` placeholders."""
    patterns = tuple(sensitive_patterns) if sensitive_patterns is not None else _SENSITIVE_PATTERNS
    out = text
    for pattern in patterns:
        out = pattern.sub("[redacted]", out)
    return out


def truncate(text: str, max_length: int) -> tuple[str, bool]:
    """Bound an excerpt; return (text, truncated)."""
    if max_length <= 0:
        raise ValueError("max_length must be positive")
    if len(text) <= max_length:
        return text, False
    return text[:max_length], True


def build_excerpt(
    text: str,
    *,
    kind: str = "content",
    source_uri: str | None = None,
    target_sha256: str | None = None,
    max_length: int = 4000,
    redact_sensitive: bool = True,
) -> UntrustedExcerpt:
    """Build a bounded, provenance-tagged excerpt from untrusted content."""
    bounded, truncated = truncate(text, max_length)
    redacted_fields: tuple[str, ...] = ()
    if redact_sensitive:
        cleaned = redact(bounded)
        if cleaned != bounded:
            redacted_fields = ("sensitive",)
        bounded = cleaned
    return UntrustedExcerpt(
        text=bounded,
        kind=kind,
        source_uri=source_uri,
        target_sha256=target_sha256,
        max_length=max_length,
        truncated=truncated,
        redacted_fields=redacted_fields,
    )


def has_injection_hints(text: str) -> list[str]:
    """Return the names of matched injection hints (additional check only).

    A hit here must never, by itself, authorize or deny anything; it only
    flags content for structured handling (length caps, provenance tags,
    allowlist-mediated tool calls).
    """
    hits = [pattern.pattern for pattern in _INJECTION_HINTS if pattern.search(text)]
    return hits


def excerpt_prompt(
    excerpts: Iterable[UntrustedExcerpt],
    max_total_length: int = 8000,
) -> str:
    """Compose multiple tagged excerpts into one prompt payload, bounded."""
    parts: list[str] = []
    used = 0
    for excerpt in excerpts:
        fragment = excerpt.to_prompt_fragment()
        if used + len(fragment) > max_total_length:
            break
        parts.append(fragment)
        used += len(fragment)
    return "\n\n".join(parts)
