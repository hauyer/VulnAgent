"""Verification resource endpoints."""

from fastapi import APIRouter, HTTPException, Request

from vulnagent.contracts import VerificationResult

router = APIRouter(prefix="/tasks", tags=["verifications"])


@router.get("/{task_id}/verifications", response_model=list[VerificationResult])
async def get_verifications(task_id: str, request: Request) -> list[VerificationResult]:
    """Return independent verification and review results for the task."""
    if request.app.state.task_manager.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found")
    context = request.app.state.orchestrator.get_context(task_id)
    return [] if context is None else context.verifications
