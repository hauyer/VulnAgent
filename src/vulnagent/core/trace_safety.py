"""Small structural guards for public runtime trace payloads."""

from collections.abc import Mapping, Sequence
from typing import Any


_PRIVATE_TRACE_FIELDS = frozenset(
    {
        "chain_of_thought",
        "private_reasoning",
        "hidden_reasoning",
        "raw_cot",
        "reasoning_tokens",
    }
)


def ensure_public_trace_payload(payload: Mapping[str, Any]) -> None:
    """Reject payloads containing private model-reasoning fields.

    The guard is deliberately structural: public summaries remain allowed,
    while reserved private fields are rejected at any nesting depth without
    examining or classifying free-text values.
    """

    if _contains_private_field(payload):
        raise ValueError(
            "Trace payload contains non-public reasoning fields"
        )


def _contains_private_field(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if _normalize_field_name(key) in _PRIVATE_TRACE_FIELDS:
                return True
            if _contains_private_field(nested):
                return True
        return False

    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return any(_contains_private_field(item) for item in value)

    return False


def _normalize_field_name(value: object) -> str:
    return str(value).strip().casefold().replace("-", "_")
