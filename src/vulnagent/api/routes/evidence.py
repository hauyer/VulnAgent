"""Evidence resource endpoints."""

from fastapi import APIRouter, HTTPException, Request
from vulnagent.contracts import Evidence

router = APIRouter(prefix="/tasks", tags=["evidence"])


@router.get("/{task_id}/evidence", response_model=list[Evidence])
async def list_evidence(task_id: str, request: Request) -> list[Evidence]:
    if request.app.state.task_manager.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return request.app.state.evidence_store.list_by_task(task_id)
