"""Report resource endpoints."""

from __future__ import annotations

import re
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from vulnagent.contracts import ReportResult
from vulnagent.acceptance import AcceptanceCalculator
from vulnagent.acceptance.batches import project_batch
from vulnagent.report import render_report_html, write_report_pdf

router = APIRouter(prefix="/tasks", tags=["reports"])


def _safe_filename_part(value: str) -> str:
    """Return a response-header-safe filename component."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)[:96] or "report"


def _enriched_report(task_id: str, request: Request) -> ReportResult:
    """Return the latest report with read-only review and acceptance projections."""
    if request.app.state.task_manager.get_task(task_id) is None:
        raise HTTPException(status_code=404, detail="Task not found")
    context = request.app.state.orchestrator.get_context(task_id)
    if context is None or not context.reports:
        raise HTTPException(status_code=404, detail="Report not generated")
    report = context.reports[-1].model_copy(deep=True)
    current_task = request.app.state.task_manager.get_task(task_id)
    if current_task is not None:
        report.content["task"] = current_task.model_dump(mode="json")
    annotations = request.app.state.review_annotations.list_for_task(task_id)
    overview = AcceptanceCalculator().build_overview(
        request.app.state.services.settings
    )
    report.content["human_review"] = {
        "annotation_count": len(annotations),
        "annotations": [item.model_dump(mode="json") for item in annotations],
        "note": (
            "人工标注是审阅意见，不会越权覆盖 VerificationResult 的正式状态。"
        ),
    }
    report.content["course_acceptance_summary"] = {
        "status_text": overview.status_text,
        "passed_groups": overview.passed_groups,
        "total_groups": overview.total_groups,
        "groups": [
            {
                "group_id": group.group_id,
                "title": group.title,
                "status": group.status.value,
                "summary": group.summary,
            }
            for group in overview.groups
        ],
        "excluded_scope": [
            "priority-8-network-filesystem-isolation",
            "priority-9-cross-process-agent-checkpoint",
        ],
    }
    report.content["acceptance_batches"] = [
        project_batch(record, request).model_dump(mode="json")
        for record in request.app.state.acceptance_batches.find_for_task(task_id)
    ]
    report.content["controlled_poc_bundles"] = [
        item.model_dump(mode="json", exclude={"code"})
        for item in request.app.state.controlled_poc.list_for_task(task_id)
    ]
    return report


@router.get("/{task_id}/report", response_model=ReportResult)
async def get_report(task_id: str, request: Request) -> ReportResult:
    """Return the latest structured report."""
    return _enriched_report(task_id, request)


@router.get("/{task_id}/report.html", response_class=HTMLResponse)
async def get_report_html(task_id: str, request: Request) -> HTMLResponse:
    """Render the latest structured report as self-contained offline HTML."""
    report = _enriched_report(task_id, request)
    safe_task_id = _safe_filename_part(task_id)
    return HTMLResponse(
        content=render_report_html(
            report.content,
            title=f"VulnAgent V0.4 · {safe_task_id} 安全审计报告",
        ),
        headers={
            "Content-Disposition": (
                f'inline; filename="VulnAgent-Audit-{safe_task_id}.html"'
            )
        },
    )


@router.get("/{task_id}/report.pdf")
async def get_report_pdf(task_id: str, request: Request) -> Response:
    """Render the latest structured report as a downloadable printable PDF."""
    report = _enriched_report(task_id, request)
    safe_task_id = _safe_filename_part(task_id)
    try:
        with TemporaryDirectory(prefix="vulnagent-report-") as temporary:
            destination = Path(temporary) / "report.pdf"
            write_report_pdf(
                report.content,
                destination,
                title=f"VulnAgent V0.4 · {safe_task_id} 安全审计报告",
            )
            content = destination.read_bytes()
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="VulnAgent-Audit-{safe_task_id}.pdf"'
            )
        },
    )
