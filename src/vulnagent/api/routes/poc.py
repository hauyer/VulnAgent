"""Controlled PoC evidence-replay endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

from vulnagent.poc import (
    ControlledPocBundle,
    ControlledPocGenerationRequest,
    PocGenerationError,
)


router = APIRouter(prefix="/tasks", tags=["controlled-poc"])


@router.get("/{task_id}/poc", response_model=list[ControlledPocBundle])
async def list_controlled_poc(task_id: str, request: Request) -> list[ControlledPocBundle]:
    """List generated controlled PoC bundles for one task."""

    try:
        return request.app.state.controlled_poc.list_for_task(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Task not found") from exc


@router.post(
    "/{task_id}/poc",
    response_model=ControlledPocBundle,
    status_code=status.HTTP_201_CREATED,
)
async def generate_controlled_poc(
    task_id: str,
    payload: ControlledPocGenerationRequest,
    request: Request,
) -> ControlledPocBundle:
    """Generate read-only evidence replay code after a confirmed verdict."""

    try:
        return request.app.state.controlled_poc.generate(task_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Task not found") from exc
    except PocGenerationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/{task_id}/poc/{bundle_id}", response_model=ControlledPocBundle)
async def get_controlled_poc(
    task_id: str,
    bundle_id: str,
    request: Request,
) -> ControlledPocBundle:
    """Return one controlled PoC bundle."""

    try:
        return request.app.state.controlled_poc.get(task_id, bundle_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Controlled PoC not found") from exc


@router.get("/{task_id}/poc/{bundle_id}/code", response_class=PlainTextResponse)
async def download_controlled_poc_code(
    task_id: str,
    bundle_id: str,
    request: Request,
) -> PlainTextResponse:
    """Download generated read-only replay source code."""

    try:
        bundle = request.app.state.controlled_poc.get(task_id, bundle_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Controlled PoC not found") from exc
    return PlainTextResponse(
        bundle.code,
        headers={"Content-Disposition": f'attachment; filename="{bundle.filename}"'},
    )


__all__ = ["router"]
