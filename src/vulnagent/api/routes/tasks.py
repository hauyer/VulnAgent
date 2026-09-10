"""Task lifecycle endpoints."""

from fastapi import APIRouter, HTTPException, Request, status
from typing import Any

from pydantic import BaseModel, Field

from vulnagent.contracts import DomainEvent, Target, TargetType, Task
from vulnagent.utils.ids import new_target_id

router = APIRouter(prefix="/tasks", tags=["tasks"])


class CreateTaskRequest(BaseModel):
    target_path: str
    target_type: TargetType
    language: str | None = None
    file_format: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.post("", response_model=Task, status_code=status.HTTP_201_CREATED)
async def create_task(payload: CreateTaskRequest, request: Request) -> Task:
    if not payload.target_path.strip():
        raise HTTPException(status_code=400, detail="target_path must not be empty")
    target = Target(
        target_id=new_target_id(),
        path=payload.target_path,
        target_type=payload.target_type,
        language=payload.language,
        file_format=payload.file_format,
        metadata=payload.metadata,
    )
    return request.app.state.task_manager.create_task(target)


@router.get("", response_model=list[Task])
async def list_tasks(request: Request) -> list[Task]:
    return request.app.state.task_manager.list_tasks()


@router.get("/{task_id}", response_model=Task)
async def get_task(task_id: str, request: Request) -> Task:
    task = request.app.state.task_manager.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.post("/{task_id}/run", response_model=Task)
async def run_task(task_id: str, request: Request) -> Task:
    if request.app.state.task_manager.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found")
    try:
        await request.app.state.orchestrator.run(task_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Task execution failed") from exc
    task = request.app.state.task_manager.get_task(task_id)
    assert task is not None
    return task


@router.get("/{task_id}/events", response_model=list[DomainEvent])
async def list_task_events(task_id: str, request: Request) -> list[DomainEvent]:
    if request.app.state.task_manager.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return request.app.state.orchestrator.event_bus.list_by_task(task_id)


@router.get("/{task_id}/trace", response_model=list[DomainEvent])
async def get_task_trace(task_id: str, request: Request) -> list[DomainEvent]:
    """Compatibility-friendly trace resource backed by structured events."""
    return await list_task_events(task_id, request)
