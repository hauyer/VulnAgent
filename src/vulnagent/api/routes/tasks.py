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


_KNOWN_PROTOCOLS = frozenset(
    {
        "real_cve_replay",
        "exploitgym_adapted_discovery",
        "external_unknown",
        "guided_variant_search",
    }
)


@router.post("", response_model=Task, status_code=status.HTTP_201_CREATED)
async def create_task(payload: CreateTaskRequest, request: Request) -> Task:
    if not payload.target_path.strip():
        raise HTTPException(status_code=400, detail="target_path must not be empty")
    if payload.metadata.get("audit_domain") == "software_code":
        normalized_path = payload.target_path.strip().replace("\\", "/")
        if payload.target_type not in {TargetType.SOURCE, TargetType.PROJECT}:
            raise HTTPException(status_code=400, detail="software-code audit requires a source/project target")
        if payload.metadata.get("local_authorized") is not True:
            raise HTTPException(status_code=403, detail="software-code audit requires explicit local authorization")
        if "://" in normalized_path or normalized_path.startswith("//"):
            raise HTTPException(status_code=400, detail="remote and network paths are forbidden for software-code audit")
        if payload.metadata.get("defensive_only") is not True:
            raise HTTPException(status_code=400, detail="software-code audit must declare defensive_only=true")
    protocol = payload.metadata.get("experiment_protocol")
    if protocol is not None and str(protocol) not in _KNOWN_PROTOCOLS:
        raise HTTPException(
            status_code=400,
            detail=f"unknown experiment_protocol {protocol!r}; expected one of {sorted(_KNOWN_PROTOCOLS)}",
        )
    manifest_id = payload.metadata.get("target_manifest_id")
    if manifest_id is not None:
        if not str(manifest_id).strip() or len(str(manifest_id)) > 128:
            raise HTTPException(status_code=400, detail="target_manifest_id must be a short opaque id")
        if protocol is None:
            raise HTTPException(status_code=400, detail="target_manifest_id requires experiment_protocol")
    target = Target(
        target_id=new_target_id(),
        path=payload.target_path,
        target_type=payload.target_type,
        language=payload.language,
        file_format=payload.file_format,
        metadata=payload.metadata,
    )
    task_metadata = {
        key: payload.metadata[key]
        for key in ("experiment_protocol", "target_manifest_id")
        if key in payload.metadata
    }
    return request.app.state.task_manager.create_task(target, metadata=task_metadata)


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
    if not task.metadata.get("run_id"):
        # Record the run id for result-archive traceability (roadmap §9).
        task = request.app.state.task_manager.update_task(
            task_id,
            metadata={"run_id": _run_id_for(task_id)},
        )
    return task


def _run_id_for(task_id: str) -> str:
    from vulnagent.contracts.common import utc_now

    return f"run-{task_id[:13]}-{utc_now().strftime('%Y%m%d%H%M%S')}"


@router.get("/{task_id}/events", response_model=list[DomainEvent])
async def list_task_events(task_id: str, request: Request) -> list[DomainEvent]:
    if request.app.state.task_manager.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return request.app.state.orchestrator.event_bus.list_by_task(task_id)


@router.get("/{task_id}/trace")
async def get_task_trace(
    task_id: str,
    request: Request,
    detail: bool = False,
    include_gt: bool = False,
) -> list[DomainEvent] | dict:
    """Compatibility-friendly trace resource backed by structured events.

    Default (``detail=false``) returns the plain event list exactly as before.
    ``detail=true`` adds per-event route reasons, evidence ids and a run
    summary, and redacts prompt/log payloads; ground truth is never returned
    (``include_gt=true`` is ignored and the field stays absent).
    """
    events = await list_task_events(task_id, request)
    if not detail:
        return events
    redacted: list[dict] = []
    evidence_ids: list[str] = []
    reasons: list[str] = []
    for event in events:
        payload = dict(event.payload or {})
        meta = dict(payload.pop("metadata", None) or {})
        for key in ("prompt", "content", "input", "query", "log"):
            if key in payload and payload[key] is not None:
                text = str(payload[key])
                if len(text) > 128:
                    payload[key] = f"[redacted: {len(text)} chars]"
        if meta.get("evidence_id"):
            evidence_ids.append(str(meta["evidence_id"]))
        if meta.get("route_reason") or meta.get("reason"):
            reasons.append(str(meta.get("route_reason") or meta.get("reason")))
        redacted.append(
            {
                "event_id": event.event_id if hasattr(event, "event_id") else f"{event.event_type}-{event.timestamp.isoformat()}",
                "message_type": event.event_type,
                "sender": event.producer,
                "receiver": None,
                "timestamp": event.timestamp.isoformat(),
                "payload": payload,
                "route_reason": meta.get("route_reason"),
                "evidence_ids": meta.get("evidence_ids") or (
                    [meta["evidence_id"]] if meta.get("evidence_id") else []
                ),
            }
        )
    task = request.app.state.task_manager.get_task(task_id)
    return {
        "events": redacted,
        "summary": {
            "task_id": task_id,
            "event_count": len(events),
            "agent_route": [e for e in redacted if e.get("route_reason")],
            "evidence_ids": sorted(set(evidence_ids)),
            "reasons": reasons,
            "status": task.status.value if task else None,
        },
        "ground_truth_included": False,
        "note": "GT and raw crash inputs are never returned by this endpoint",
    }
