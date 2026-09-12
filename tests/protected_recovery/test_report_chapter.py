"""The report consumes recovery evidence without re-running analyzers."""

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    ReportRequest,
    Target,
    TargetType,
    Task,
)
from vulnagent.report.generator import StructuredReportGenerator
from vulnagent.report.html import render_report_html


async def test_report_contains_binary_protection_chapter() -> None:
    task = Task(
        task_id="task",
        target=Target(target_id="target", path="owned.exe", target_type=TargetType.BINARY),
    )
    evidence = [
        Evidence(
            evidence_id="restore",
            task_id="task",
            evidence_type=EvidenceType.TOOL_RESULT,
            source="program_restoration",
            description="restored",
            data={
                "status": "restored",
                "success": True,
                "protection": {"selected": {"family": "UPX", "level": 1}},
                "metrics": {"elapsed_ms": 12},
                "validation": {"parseable": True, "imports": 3},
            },
            reliability=0.9,
            created_by="program_restoration",
        ),
        Evidence(
            evidence_id="deobf",
            task_id="task",
            evidence_type=EvidenceType.TOOL_RESULT,
            source="code_deobfuscation",
            description="recovered",
            data={"readability": {"before": 30, "after": 78}, "detected_types": ["bogus_control_flow"]},
            reliability=0.8,
            created_by="code_deobfuscation",
        ),
    ]
    report = await StructuredReportGenerator().generate(ReportRequest(task=task, evidence=evidence))
    chapter = report.content["binary_protection_analysis"]
    assert chapter["restoration"]["success"] is True
    assert chapter["deobfuscation"]["readability"]["after"] == 78
    assert len(chapter["evidence_chain"]) == 2
    rendered = render_report_html(report.content)
    assert "二进制程序保护分析专项" in rendered
    assert "UPX" in rendered
    assert "30 → 78" in rendered
