"""Self-contained report HTML is escaped, useful and deterministic."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.export_report_html import _report_content
from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    ReportRequest,
    Target,
    TargetType,
    Task,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityStatus,
)
from vulnagent.report.generator import StructuredReportGenerator
from vulnagent.report.html import render_report_html, write_report_html
from vulnagent.report.pdf import write_report_pdf


async def _content() -> dict[str, object]:
    task = Task(
        task_id="task-html",
        target=Target(
            target_id="target-html",
            path="<script>alert('target')</script>.py",
            target_type=TargetType.SOURCE,
        ),
    )
    evidence = Evidence(
        evidence_id="evidence-html",
        task_id=task.task_id,
        evidence_type=EvidenceType.CODE_SNIPPET,
        source="source-audit",
        description="escaped <img src=x onerror=alert(1)>",
        reliability=0.9,
        created_by="source_audit",
    )
    finding = VulnerabilityCandidate(
        vulnerability_id="finding-html",
        task_id=task.task_id,
        title="Unsafe <script>alert(1)</script>",
        vulnerability_type="command_injection",
        cwe_id="CWE-78",
        description="User input reaches a command sink.",
        target_id=task.target.target_id,
        source_agent="source_audit",
        confidence=0.88,
        severity="HIGH",
        evidence_ids=[evidence.evidence_id],
    )
    verification = VerificationResult(
        vulnerability_id=finding.vulnerability_id,
        task_id=task.task_id,
        status=VulnerabilityStatus.CONFIRMED,
        confidence=0.91,
        rationale="Independent structured evidence corroborates the sink.",
        evidence_ids=[evidence.evidence_id],
    )
    report = await StructuredReportGenerator().generate(
        ReportRequest(
            task=task,
            findings=[finding],
            evidence=[evidence],
            verifications=[verification],
        )
    )
    return report.content


@pytest.mark.asyncio
async def test_html_contains_report_chain_and_escapes_untrusted_text() -> None:
    output = render_report_html(await _content(), title="Report <unsafe>")

    assert "Content-Security-Policy" in output
    assert "finding-html" not in output  # IDs are represented through linked evidence, not raw metadata.
    assert "evidence-html" in output
    assert "已确认" in output
    assert "修复建议" in output
    assert "CWE CWE-78" not in output
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in output
    assert "<script>alert(1)</script>" not in output
    assert "<img src=x onerror=alert(1)>" not in output


@pytest.mark.asyncio
async def test_html_writer_is_atomic_and_has_no_external_dependencies(
    tmp_path: Path,
) -> None:
    destination = write_report_html(await _content(), tmp_path / "report.html")

    text = destination.read_text(encoding="utf-8")
    assert destination.is_file()
    assert not destination.with_suffix(".html.tmp").exists()
    assert "<link " not in text
    assert "<script" not in text
    assert "http://" not in text and "https://" not in text


def test_cli_report_content_accepts_bundle_and_report_result_shapes() -> None:
    content = {"task": {}, "summary": {}}

    assert _report_content({"report": content}) == content
    assert _report_content({"content": content}) == content
    assert _report_content(content) == content
    with pytest.raises(ValueError, match="structured VulnAgent report"):
        _report_content({"summary": {}})


@pytest.mark.asyncio
async def test_pdf_writer_creates_atomic_printable_artifact(tmp_path: Path) -> None:
    destination = write_report_pdf(await _content(), tmp_path / "report.pdf")

    assert destination.read_bytes().startswith(b"%PDF-")
    assert destination.stat().st_size > 5_000
    assert not destination.with_suffix(".pdf.tmp").exists()
