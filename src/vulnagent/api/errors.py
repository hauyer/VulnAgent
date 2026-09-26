"""S6 (work-package F): uniform API error envelope.

Every error response carries ``code, message, retryable, detail_ref?`` plus an
optional ``run_id``; the legacy ``detail`` field is kept so pre-existing
clients keep working.  ``detail_ref`` points at an internal log id and never
leaks a host-absolute path.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, Field


class APIErrorCode:
    TARGET_NOT_ADMITTED = "TARGET_NOT_ADMITTED"
    ISOLATION_UNAVAILABLE = "ISOLATION_UNAVAILABLE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    RUN_TIMEOUT = "RUN_TIMEOUT"
    EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
    GT_NOT_AVAILABLE = "GT_NOT_AVAILABLE"
    NOT_FOUND = "NOT_FOUND"
    BAD_REQUEST = "BAD_REQUEST"


class APIErrorDetail(BaseModel):
    code: str
    message: str
    run_id: str | None = None
    retryable: bool = False
    detail_ref: str | None = None
    detail: str | None = None  # legacy compatibility alias


def api_error(
    status_code: int,
    code: str,
    message: str,
    *,
    run_id: str | None = None,
    retryable: bool = False,
    detail_ref: str | None = None,
) -> HTTPException:
    detail = APIErrorDetail(
        code=code,
        message=message,
        run_id=run_id,
        retryable=retryable,
        detail_ref=detail_ref,
        detail=message,
    )
    return HTTPException(status_code=status_code, detail=detail.model_dump(exclude_none=True))


def not_found(message: str = "resource not found") -> HTTPException:
    return api_error(404, APIErrorCode.NOT_FOUND, message)


def bad_request(message: str = "invalid request") -> HTTPException:
    return api_error(400, APIErrorCode.BAD_REQUEST, message)


def _envelope_from_exception(exc: HTTPException) -> dict[str, Any]:
    """Build the envelope from an existing HTTPException, preserving `detail`."""
    detail = exc.detail
    if isinstance(detail, dict) and "code" in detail:
        return detail  # already enveloped
    if isinstance(detail, str):
        return {
            "code": APIErrorCode.BAD_REQUEST if exc.status_code < 500 else "INTERNAL_ERROR",
            "message": detail,
            "retryable": exc.status_code >= 500,
            "detail": detail,
        }
    return {
        "code": APIErrorCode.BAD_REQUEST if exc.status_code < 500 else "INTERNAL_ERROR",
        "message": str(detail),
        "retryable": exc.status_code >= 500,
        "detail": str(detail),
    }
