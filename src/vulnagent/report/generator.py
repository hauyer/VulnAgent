"""Structured, evidence-first report generation."""

from typing import Any

from vulnagent.contracts import AnalysisContext, ReportRequest, ReportResult, VulnerabilityStatus
from vulnagent.evidence.graph import build_evidence_graph


def generate_report(context: AnalysisContext) -> dict[str, Any]:
    """Compatibility helper for callers that hold an ``AnalysisContext``."""
    return _build_content(ReportRequest(
        task=context.task,
        findings=context.findings,
        evidence=context.evidence,
        verifications=context.verifications,
    ))


class MockReportGenerator:
    """Generate a structured report without reading capability internals.

    The class name remains for composition-root compatibility during V0.2; its
    output is deliberately driven by the public, structured request rather than
    a synthesized LLM narrative.
    """

    async def generate(self, request: ReportRequest) -> ReportResult:
        content = _build_content(request)
        return ReportResult(task_id=request.task.task_id, content=content, artifact_uri=f"memory://reports/{request.task.task_id}", metadata={"mock": True, "structured": True})


def _build_content(request: ReportRequest) -> dict[str, Any]:
    evidence_by_id = {item.evidence_id: item for item in request.evidence}
    verifications_by_finding = {item.vulnerability_id: item for item in request.verifications}
    missing_evidence_ids: set[str] = set()
    findings: list[dict[str, Any]] = []

    for finding in request.findings:
        verification = verifications_by_finding.get(finding.vulnerability_id)
        related_ids = set(finding.evidence_ids)
        if verification is not None:
            related_ids.update(verification.evidence_ids)
        missing_evidence_ids.update(evidence_id for evidence_id in related_ids if evidence_id not in evidence_by_id)
        findings.append({
            "finding": finding.model_dump(mode="json"),
            "verification": verification.model_dump(mode="json") if verification else None,
            "evidence": [evidence_by_id[evidence_id].model_dump(mode="json") for evidence_id in sorted(related_ids) if evidence_id in evidence_by_id],
        })

    statuses = {status.value: 0 for status in VulnerabilityStatus}
    for finding in request.findings:
        statuses[finding.status.value] += 1

    return {
        "task": request.task.model_dump(mode="json"),
        "summary": {
            "finding_count": len(request.findings),
            "evidence_count": len(request.evidence),
            "verification_count": len(request.verifications),
            "findings_by_status": statuses,
        },
        "findings": findings,
        "evidence": [item.model_dump(mode="json") for item in request.evidence],
        "verifications": [item.model_dump(mode="json") for item in request.verifications],
        "evidence_graph": build_evidence_graph(request.findings, request.evidence, request.verifications),
        "limitations": {
            "missing_evidence_ids": sorted(missing_evidence_ids),
            "unverified_finding_ids": sorted(
                finding.vulnerability_id
                for finding in request.findings
                if finding.vulnerability_id not in verifications_by_finding
            ),
        },
        "mock": True,
    }
