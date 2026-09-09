"""Deterministic severity helpers for the report layer.

The report module must not import ``vulnagent.verification`` (architectural
boundary) and must never raise on an unknown severity string, so this module
carries a lenient, self-contained copy of severity handling.

Severity follows the V0.1 protocol: ``INFO``, ``LOW``, ``MEDIUM``, ``HIGH``,
``CRITICAL``.  Missing / unknown values fall into the ``UNKNOWN`` bucket with
rank 0 so every finding can be displayed and sorted deterministically.
"""

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

_RANK_TO_SEVERITY: dict[int, str] = {rank: label for label, rank in SEVERITY_RANK.items()}

SEVERITY_CN: dict[str, str] = {
    "CRITICAL": "严重",
    "HIGH": "高",
    "MEDIUM": "中",
    "LOW": "低",
    "INFO": "信息",
    "UNKNOWN": "未知",
}

UNKNOWN_SEVERITY = "UNKNOWN"


def normalize_severity(value: str | None) -> str | None:
    """Return the canonical uppercase severity, or ``None`` when unknown/missing."""
    if value is None:
        return None
    normalized = str(value).strip().upper()
    return normalized if normalized in SEVERITY_RANK else None


def severity_rank(value: str | None) -> int:
    """Rank a severity (CRITICAL=5 ... INFO=1); unknown/missing -> 0."""
    normalized = normalize_severity(value)
    return SEVERITY_RANK[normalized] if normalized is not None else 0


def severity_label(value: str | None) -> str:
    """Canonical uppercase label or ``UNKNOWN``; never raises, never returns None."""
    return normalize_severity(value) or UNKNOWN_SEVERITY


def severity_cn(value: str | None) -> str:
    """Chinese display label for a severity value."""
    return SEVERITY_CN[severity_label(value)]


def severity_label_from_rank(rank: int) -> str:
    """Reverse lookup: severity label for a rank (0 -> ``UNKNOWN``)."""
    return _RANK_TO_SEVERITY.get(rank, UNKNOWN_SEVERITY)
