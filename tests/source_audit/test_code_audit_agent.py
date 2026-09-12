"""Defensive software-code agent tests."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from vulnagent.agents.code_audit_agent import CodeAuditAgent
from vulnagent.contracts import (
    AnalysisContext,
    EvidenceType,
    Target,
    TargetType,
    Task,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)
from vulnagent.llm.base import BaseLLM
from vulnagent.llm.mock import MockLLM
from vulnagent.analyzers.source.audit import MultiLanguageSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.bootstrap import build_application, build_mock_capabilities
from vulnagent.contracts import EventType


class ReviewLLM(BaseLLM):
    async def generate(self, prompt: str, **kwargs: object) -> str:
        assert "taint_path" in prompt
        return json.dumps(
            {
                "review_result": "likely_true_positive",
                "triggerability": "conditional",
                "recommended_severity": "HIGH",
                "confidence": 0.81,
                "summary": "输入长度到达拷贝操作，未观察到支配该操作的容量检查。",
                "observed_guards": [],
                "supporting_facts": ["存在静态污点路径。"],
                "contradicting_facts": [],
                "missing_evidence": ["受控运行结果"],
                "remediation_summary": "增加容量上限检查。",
                "remediation_actions": ["写入前比较输入长度与目标容量。"],
                "safety": {"defensive_only": True, "prohibited_content_emitted": False},
            },
            ensure_ascii=False,
        )


def _context() -> tuple[Task, AnalysisContext]:
    task = Task(
        task_id="task-code-agent",
        target=Target(
            target_id="target-code-agent",
            path="local.c",
            target_type=TargetType.SOURCE,
        ),
    )
    finding = VulnerabilityCandidate(
        vulnerability_id="finding-code-agent",
        task_id=task.task_id,
        title="bounded copy review",
        vulnerability_type="buffer_overflow",
        cwe_id="CWE-120",
        description="Defensive candidate.",
        target_id=task.target.target_id,
        location=VulnerabilityLocation(file_path="local.c", line_start=8),
        source_agent="source_audit",
        confidence=0.8,
        severity="HIGH",
        metadata={
            "audit_domain": "software_code",
            "rule_id": "VA-NATIVE-MEM-001",
            "taint_path": ["source:parameter@2", "sink:copy@8"],
            "cfg_path": [{"node_id": "n1", "line": 8}],
        },
    )
    return task, AnalysisContext(task=task, findings=[finding])


@pytest.mark.asyncio
async def test_code_audit_agent_emits_auxiliary_evidence_only() -> None:
    task, context = _context()
    result = await CodeAuditAgent(ReviewLLM()).run(task, context)

    assert result.findings == []
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.evidence_type is EvidenceType.MODEL_REASONING_SUMMARY
    assert evidence.data["finding_id"] == "finding-code-agent"
    assert evidence.data["review_result"] == "likely_true_positive"
    assert evidence.data["safety"]["defensive_only"] is True
    assert result.messages[0].payload["verdict_authority"] == "verification"


@pytest.mark.asyncio
async def test_code_audit_agent_has_deterministic_fallback() -> None:
    task, context = _context()
    result = await CodeAuditAgent().run(task, context)

    assert result.evidence[0].data["review_result"] == "uncertain"
    assert result.evidence[0].data["remediation_actions"]
    assert result.evidence[0].data["model_status"] == "not_configured"


@pytest.mark.asyncio
async def test_code_audit_agent_is_routed_before_verification(tmp_path: Path) -> None:
    path = tmp_path / "service.c"
    path.write_text(
        "void copy_name(char *input) { char value[8]; strcpy(value, input); }\n",
        encoding="utf-8",
    )
    capabilities = replace(
        build_mock_capabilities(),
        source_parser=SourceProjectParser(),
        source_auditor=MultiLanguageSourceAuditor(),
        code_audit_enabled=True,
    )
    services = build_application(capabilities, llm=MockLLM())
    task = services.task_manager.create_task(
        Target(
            target_id="target-runtime-code-audit",
            path=str(path),
            target_type=TargetType.SOURCE,
        )
    )

    context = await services.orchestrator.run(task.task_id)
    routes = [
        event.payload["route"]
        for event in services.event_bus.list_by_task(task.task_id)
        if event.event_type is EventType.AGENT_STARTED
    ]

    assert routes.index("source_analysis") < routes.index("code_audit") < routes.index("verification")
    assert any(
        item.source == "code_audit"
        and item.evidence_type is EvidenceType.MODEL_REASONING_SUMMARY
        for item in context.evidence
    )
