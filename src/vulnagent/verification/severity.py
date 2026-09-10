"""V0.1 severity normalization."""

VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def normalize_severity(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.upper()
    if normalized not in VALID_SEVERITIES:
        raise ValueError(f"Unknown severity: {value}")
    return normalized

