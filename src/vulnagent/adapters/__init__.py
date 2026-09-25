"""Third-party integration boundary; business state must not be mutated here."""

from .normalize import (
    external_finding_to_candidate,
    new_candidate_id,
    tool_result_status,
    tool_result_summary,
)

__all__ = [
    "external_finding_to_candidate",
    "new_candidate_id",
    "tool_result_status",
    "tool_result_summary",
]
