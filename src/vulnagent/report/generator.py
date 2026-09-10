"""Structured report generator."""

from typing import Any
from vulnagent.contracts import AnalysisContext, ReportRequest, ReportResult


def generate_report(context: AnalysisContext) -> dict[str, Any]:
    return {"task": context.task.model_dump(mode="json"), "findings": [item.model_dump(mode="json") for item in context.findings], "evidence": [item.model_dump(mode="json") for item in context.evidence], "mock": True}


class MockReportGenerator:
    """Generate a structured report without reading capability internals."""

    async def generate(self, request: ReportRequest) -> ReportResult:
        content = {"task": request.task.model_dump(mode="json"), "findings": [item.model_dump(mode="json") for item in request.findings], "evidence": [item.model_dump(mode="json") for item in request.evidence], "verifications": [item.model_dump(mode="json") for item in request.verifications], "mock": True}
        return ReportResult(task_id=request.task.task_id, content=content, artifact_uri=f"memory://reports/{request.task.task_id}", metadata={"mock": True})
