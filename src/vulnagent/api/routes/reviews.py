"""Manual review annotation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from vulnagent.review import HumanReviewAnnotation, HumanReviewUpdate


router = APIRouter(prefix="/tasks", tags=["human-review"])


def _ensure_finding(task_id: str, vulnerability_id: str, request: Request) -> None:
    if request.app.state.task_manager.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found")
    context = request.app.state.orchestrator.get_context(task_id)
    if context is None or not any(
        item.vulnerability_id == vulnerability_id for item in context.findings
    ):
        raise HTTPException(status_code=404, detail="Finding not found")


@router.get("/{task_id}/reviews", response_model=list[HumanReviewAnnotation])
async def list_reviews(task_id: str, request: Request) -> list[HumanReviewAnnotation]:
    """Read back all human annotations for a task."""

    if request.app.state.task_manager.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return request.app.state.review_annotations.list_for_task(task_id)


@router.put(
    "/{task_id}/findings/{vulnerability_id}/review",
    response_model=HumanReviewAnnotation,
)
async def put_review(
    task_id: str,
    vulnerability_id: str,
    payload: HumanReviewUpdate,
    request: Request,
) -> HumanReviewAnnotation:
    """Save a correction note without changing the formal verifier verdict."""

    _ensure_finding(task_id, vulnerability_id, request)
    return request.app.state.review_annotations.put(task_id, vulnerability_id, payload)
