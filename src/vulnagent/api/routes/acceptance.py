"""Course-test acceptance matrix endpoints (read-only aggregation + runs)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from vulnagent.acceptance import (
    CustomAcceptanceBatch,
    CustomAcceptanceBatchCreate,
    AcceptanceCalculator,
    AcceptanceGroup,
    AcceptanceOverview,
    AcceptanceStatus,
    ProviderStatus,
)
from vulnagent.acceptance.batches import (
    attach_batch_metadata,
    project_batch,
    validate_batch_tasks,
)
from vulnagent.acceptance.calculator import GROUP_LLM, GROUP_OBFUSCATED, GROUP_PACKED
from vulnagent.acceptance.smoke import run_provider_smoke

router = APIRouter(prefix="/acceptance", tags=["acceptance"])

_GROUP_IDS = {GROUP_LLM, GROUP_PACKED, GROUP_OBFUSCATED}
_PROVIDER_KEYS = ("deepseek", "glm", "kimi")


class RunGroupRequest(BaseModel):
    """Optional provider selection for group A runs."""

    providers: list[str] | None = Field(default=None, min_length=1)


def _calculator(request: Request) -> AcceptanceCalculator:
    return AcceptanceCalculator()


def _settings(request: Request):
    return request.app.state.services.settings


@router.get("/batches", response_model=list[CustomAcceptanceBatch])
async def list_custom_batches(request: Request) -> list[CustomAcceptanceBatch]:
    """List custom batches with live task/file/model/report projections."""

    return [
        project_batch(record, request)
        for record in request.app.state.acceptance_batches.list()
    ]


@router.post("/batches", response_model=CustomAcceptanceBatch, status_code=201)
async def create_custom_batch(
    payload: CustomAcceptanceBatchCreate,
    request: Request,
) -> CustomAcceptanceBatch:
    """Persist explicit A/B/C task associations without inventing metrics."""

    try:
        validated = validate_batch_tasks(
            payload,
            request.app.state.task_manager.list_tasks(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record = request.app.state.acceptance_batches.create(validated)
    attach_batch_metadata(request.app.state.task_manager, record)
    return project_batch(record, request)


@router.get("/batches/{batch_id}", response_model=CustomAcceptanceBatch)
async def get_custom_batch(batch_id: str, request: Request) -> CustomAcceptanceBatch:
    """Return one custom batch and its current linked report status."""

    record = request.app.state.acceptance_batches.get(batch_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Acceptance batch not found")
    return project_batch(record, request)


@router.get("/overview", response_model=AcceptanceOverview)
async def get_overview(request: Request) -> AcceptanceOverview:
    """Return the honest three-group course-test acceptance matrix."""
    return _calculator(request).build_overview(_settings(request))


@router.get("/providers", response_model=list[ProviderStatus])
async def get_providers(request: Request) -> list[ProviderStatus]:
    """Return configured LLM provider status without credentials."""
    overview = _calculator(request).build_overview(_settings(request))
    group_a = next((group for group in overview.groups if group.group_id == GROUP_LLM), None)
    return group_a.providers if group_a else []


@router.get("/groups/{group_id}", response_model=AcceptanceGroup)
async def get_group(group_id: str, request: Request) -> AcceptanceGroup:
    """Return one test group with its targets/providers and conditions."""
    normalized = group_id.strip().casefold()
    if normalized not in _GROUP_IDS:
        raise HTTPException(status_code=404, detail="Unknown acceptance group")
    overview = _calculator(request).build_overview(_settings(request))
    group = next((item for item in overview.groups if item.group_id == normalized), None)
    if group is None:
        raise HTTPException(status_code=404, detail="Unknown acceptance group")
    return group


@router.post("/groups/{group_id}/run", response_model=AcceptanceGroup)
async def run_group(
    group_id: str,
    request: Request,
    body: RunGroupRequest | None = None,
) -> AcceptanceGroup:
    """Run one group's safe verification step and return refreshed status.

    Group A performs a bounded real provider smoke check (one call per
    selected provider; defaults to every configured provider). Groups B and C
    re-audit sample intake readiness without executing any target. Neither
    path invokes a dynamic PoC.
    """
    normalized = group_id.strip().casefold()
    if normalized not in _GROUP_IDS:
        raise HTTPException(status_code=404, detail="Unknown acceptance group")
    if normalized == GROUP_LLM:
        settings = _settings(request)
        configured = [
            name
            for name in _PROVIDER_KEYS
            if getattr(settings, f"{name}_api_key", None)
        ]
        selected_names = body.providers if body and body.providers else configured
        selected = [name.strip().casefold() for name in selected_names if name and name.strip()]
        selected = list(dict.fromkeys(selected))  # de-duplicate, keep order
        if len(selected) < 1:
            raise HTTPException(
                status_code=400,
                detail="Group A requires at least one configured real provider key",
            )
        unknown = [name for name in selected if name not in _PROVIDER_KEYS]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown provider(s): {', '.join(unknown)}",
            )
        missing_keys = [name for name in selected if name not in configured]
        if missing_keys:
            raise HTTPException(
                status_code=400,
                detail=f"Provider(s) not configured: {', '.join(missing_keys)}",
            )
        await run_provider_smoke(settings, providers=selected)
    overview = _calculator(request).build_overview(_settings(request))
    group = next((item for item in overview.groups if item.group_id == normalized), None)
    if group is None:
        raise HTTPException(status_code=404, detail="Unknown acceptance group")
    return group


__all__ = ["router", "AcceptanceStatus"]
