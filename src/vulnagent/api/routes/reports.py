"""Report resource endpoints."""

from fastapi import APIRouter, HTTPException, Request
from vulnagent.contracts import ReportResult

router = APIRouter(prefix="/tasks", tags=["reports"])


@router.get("/{task_id}/report", response_model=ReportResult)
async def get_report(task_id: str, request: Request) -> ReportResult:
    if request.app.state.task_manager.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found")
    context = request.app.state.orchestrator.get_context(task_id)
    if context is None or not context.reports:
        raise HTTPException(status_code=404, detail="Report not generated")
    return context.reports[-1]
