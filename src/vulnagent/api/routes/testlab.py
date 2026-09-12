"""Local-only three-category test laboratory endpoints."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status

from vulnagent.testlab import LabArchiveResult, LabCapability, LabRun, LabRunRequest


router = APIRouter(prefix="/test-lab", tags=["test-lab"])


@router.get("/capabilities", response_model=list[LabCapability])
async def get_capabilities(request: Request) -> list[LabCapability]:
    """Return supported targets, stages, and honest safety boundaries."""

    return request.app.state.test_lab.capabilities()


@router.get("/runs", response_model=list[LabRun])
async def list_runs(request: Request) -> list[LabRun]:
    """Return process-local run history, newest first."""

    return request.app.state.test_lab.list_runs()


@router.get("/runs/{run_id}", response_model=LabRun)
async def get_run(run_id: str, request: Request) -> LabRun:
    """Return one run including stage logs and structured results."""

    run = request.app.state.test_lab.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Test-lab run not found")
    return run


@router.post("/runs", response_model=LabRun, status_code=status.HTTP_202_ACCEPTED)
async def create_run(
    payload: LabRunRequest,
    request: Request,
    background_tasks: BackgroundTasks,
) -> LabRun:
    """Queue a bounded run and return immediately for frontend polling."""

    service = request.app.state.test_lab
    run = service.start(payload)
    background_tasks.add_task(service.execute, run.run_id, payload)
    return run


@router.post("/runs/{run_id}/cancel", response_model=LabRun)
async def cancel_run(run_id: str, request: Request) -> LabRun:
    """Cancel a queued/running laboratory run while retaining completed results."""

    try:
        return request.app.state.test_lab.cancel(run_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Test-lab run not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/runs/{run_id}/archive/{task_id}",
    response_model=LabArchiveResult,
)
async def archive_run_task(run_id: str, task_id: str, request: Request) -> LabArchiveResult:
    """Record one completed protected-binary task in the vulnerability dossier."""

    try:
        return request.app.state.test_lab.archive(run_id, task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Test-lab run not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
