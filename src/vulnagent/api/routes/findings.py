"""Finding query endpoint."""

from fastapi import APIRouter, HTTPException, Request

from vulnagent.contracts import VulnerabilityCandidate

router = APIRouter(prefix="/tasks", tags=["findings"])


@router.get("/{task_id}/findings", response_model=list[VulnerabilityCandidate])
async def get_findings(task_id: str, request: Request) -> list[VulnerabilityCandidate]:
    if request.app.state.task_manager.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found")
    context = request.app.state.orchestrator.get_context(task_id)
    return [] if context is None else context.findings
