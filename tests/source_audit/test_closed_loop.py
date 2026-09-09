"""Integration coverage for a real P2 parser and P3 source auditor."""

from dataclasses import replace
from pathlib import Path

from vulnagent.analyzers.source.audit import PythonSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.bootstrap import build_application, build_mock_capabilities
from vulnagent.contracts import EvidenceType, Target, TargetType, TaskStatus


async def test_real_source_audit_runs_in_the_existing_closed_loop(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "import os\n\ndef run():\n    os.system(input())\n",
        encoding="utf-8",
    )
    capabilities = replace(
        build_mock_capabilities(),
        source_parser=SourceProjectParser(),
        source_auditor=PythonSourceAuditor(),
    )
    services = build_application(capabilities)
    task = services.task_manager.create_task(
        Target(
            target_id="source-audit-target",
            path=str(tmp_path),
            target_type=TargetType.SOURCE,
        )
    )

    context = await services.orchestrator.run(task.task_id)

    assert context.task.status is TaskStatus.COMPLETED
    finding = next(
        item
        for item in context.findings
        if item.metadata.get("rule_id") == "VA-PY-CMD-001"
    )
    source_evidence = [
        item
        for item in context.evidence
        if item.evidence_type is EvidenceType.SOURCE_LOCATION
    ]
    assert source_evidence
    assert source_evidence[0].evidence_id in finding.evidence_ids
    assert context.reports
