"""L1: ContextSliceProvider adoption inside CodeAuditAgent."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnagent.agents.code_audit_agent import CodeAuditAgent
from vulnagent.analyzers.source.audit.context_slice import ContextSliceProvider
from vulnagent.contracts import (
    AnalysisContext,
    EvidenceType,
    Target,
    TargetType,
    Task,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)


def _write_demo_project(root: Path) -> None:
    (root / "parse.c").write_text(
        "int parse_name(const char* input, char* out, size_t cap) {\n"
        "  if (!input || !out) return -1;\n"
        "  strcpy(out, input);\n"
        "  return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "main.c").write_text(
        "extern int parse_name(const char*, char*, size_t);\n"
        "int main(void) { char buf[8]; parse_name(\"x\", buf, 8); return 0; }\n",
        encoding="utf-8",
    )


def _task_and_context(root: Path) -> tuple[Task, AnalysisContext]:
    task = Task(
        task_id="task-l1",
        target=Target(
            target_id="target-l1",
            path=str(root),
            target_type=TargetType.PROJECT,
        ),
    )
    finding = VulnerabilityCandidate(
        vulnerability_id="finding-l1",
        task_id=task.task_id,
        title="bounded copy review",
        vulnerability_type="buffer_overflow",
        cwe_id="CWE-120",
        description="Defensive candidate.",
        target_id=task.target.target_id,
        location=VulnerabilityLocation(file_path="parse.c", line_start=3),
        source_agent="source_audit",
        confidence=0.8,
        severity="HIGH",
        metadata={
            "audit_domain": "software_code",
            "sink": "strcpy",
            "entry_point": "parse_name",
            "taint_path": ["source:parameter@1", "sink:strcpy@3"],
        },
    )
    return task, AnalysisContext(task=task, findings=[finding])


@pytest.mark.asyncio
async def test_code_audit_collects_bounded_slices(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _write_demo_project(root)
    task, context = _task_and_context(root)
    agent = CodeAuditAgent(context_slice_provider=ContextSliceProvider(max_files=4))
    result = await agent.run(task, context)

    snippet_evidence = [
        item for item in result.evidence if item.evidence_type is EvidenceType.CODE_SNIPPET
    ]
    assert snippet_evidence, "expected bounded CODE_SNIPPET evidence"
    for item in snippet_evidence:
        assert item.source == "context_slice_provider"
        data = item.data
        assert data["source_kind"] in {"symbol_definition", "user_request"}
        assert 0 < len(data["text"]) <= 2000
        assert "strcpy" in data["text"] or "parse_name" in data["text"]

    assessment = result.messages[0].payload["assessments"][0]
    assert assessment["context_slice_count"] >= 1

    # model opinion stays auxiliary: no verdict authority shift
    assert result.messages[0].payload["verdict_authority"] == "verification"


@pytest.mark.asyncio
async def test_code_audit_without_provider_keeps_old_shape(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _write_demo_project(root)
    task, context = _task_and_context(root)
    result = await CodeAuditAgent().run(task, context)  # provider None
    assert all(item.evidence_type is EvidenceType.MODEL_REASONING_SUMMARY for item in result.evidence)
    assert result.messages[0].payload["assessments"][0]["context_slice_count"] == 0


@pytest.mark.asyncio
async def test_slices_never_leave_admitted_root(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _write_demo_project(root)
    # a candidate whose symbols do not exist anywhere: no slices, no crash
    task = Task(
        task_id="task-l1b",
        target=Target(
            target_id="target-l1b",
            path=str(root),
            target_type=TargetType.PROJECT,
        ),
    )
    finding = VulnerabilityCandidate(
        vulnerability_id="finding-l1b",
        task_id=task.task_id,
        title="no-match candidate",
        vulnerability_type="null_pointer",
        cwe_id="CWE-476",
        description="Nothing should match.",
        target_id=task.target.target_id,
        source_agent="source_audit",
        confidence=0.5,
        severity="MEDIUM",
        metadata={"audit_domain": "software_code", "sink": "no_such_symbol_xyz"},
    )
    agent = CodeAuditAgent(context_slice_provider=ContextSliceProvider())
    result = await agent.run(task, AnalysisContext(task=task, findings=[finding]))
    assert all(item.evidence_type is EvidenceType.MODEL_REASONING_SUMMARY for item in result.evidence)
