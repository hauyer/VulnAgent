"""Source audit agent coordinating parser, auditor and evidence contracts."""

from typing import Any

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import (
    AgentMessage,
    AgentMessageType,
    AgentResult,
    AnalysisContext,
    Evidence,
    EvidenceType,
    ProjectInput,
    SourceAuditor,
    SourceParser,
    Task,
    VulnerabilityCandidate,
)
from vulnagent.utils.ids import new_evidence_id, new_message_id


class SourceAuditAgent(BaseAgent):
    """Run source capabilities and normalize their traceable evidence."""

    name = "source_audit"

    def __init__(self, parser: SourceParser, auditor: SourceAuditor) -> None:
        self.parser = parser
        self.auditor = auditor

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        parsed = await self.parser.analyze(
            ProjectInput(
                task_id=task.task_id,
                target_id=task.target.target_id,
                project_path=task.target.path,
            )
        )
        findings = await self.auditor.audit(parsed)
        is_mock = bool(parsed.metadata.get("mock")) or (
            bool(findings) and all(item.metadata.get("mock") for item in findings)
        )
        evidence: list[Evidence] = []
        messages = [
            AgentMessage(
                message_id=new_message_id(),
                task_id=task.task_id,
                sender=self.name,
                receiver="supervisor",
                message_type=AgentMessageType.ANALYSIS_RESULT,
                payload={
                    "finding_count": len(findings),
                    "analysis": parsed.model_dump(mode="json"),
                    "mock": is_mock,
                },
            )
        ]

        for finding in findings:
            finding_evidence = self._evidence_for(task, finding, is_mock=is_mock)
            finding.evidence_ids.extend(item.evidence_id for item in finding_evidence)
            evidence.extend(finding_evidence)
            messages.append(
                AgentMessage(
                    message_id=new_message_id(),
                    task_id=task.task_id,
                    sender=self.name,
                    receiver="verification",
                    message_type=AgentMessageType.VULNERABILITY_CANDIDATE,
                    payload={
                        "vulnerability_id": finding.vulnerability_id,
                        "producer": finding.producer,
                        "mock": is_mock,
                    },
                    evidence_ids=[item.evidence_id for item in finding_evidence],
                )
            )

        return AgentResult(
            agent_name=self.name,
            messages=messages,
            findings=findings,
            evidence=evidence,
        )

    def _evidence_for(
        self,
        task: Task,
        finding: VulnerabilityCandidate,
        *,
        is_mock: bool,
    ) -> list[Evidence]:
        """Build evidence only from facts emitted by the audit capability."""
        location = (
            finding.location.model_dump(mode="json") if finding.location else None
        )
        items = [
            self._evidence(
                task,
                EvidenceType.SOURCE_LOCATION,
                "Source audit recorded the candidate's concrete source location.",
                {
                    "finding_id": finding.vulnerability_id,
                    "location": location,
                    "producer": finding.producer,
                    "mock": is_mock,
                },
                0.5 if is_mock else 0.9,
            )
        ]

        snippet = finding.metadata.get("snippet")
        if isinstance(snippet, str) and snippet:
            items.append(
                self._evidence(
                    task,
                    EvidenceType.CODE_SNIPPET,
                    "Bounded source snippet at the detected sink.",
                    {
                        "finding_id": finding.vulnerability_id,
                        "snippet": snippet,
                        "location": location,
                    },
                    0.9,
                )
            )

        taint_path = finding.metadata.get("taint_path")
        if isinstance(taint_path, list) and taint_path:
            items.append(
                self._evidence(
                    task,
                    EvidenceType.TAINT_PATH,
                    "Best-effort intraprocedural taint path from source to sink.",
                    {
                        "finding_id": finding.vulnerability_id,
                        "path": taint_path,
                        "source_kinds": finding.metadata.get("source_kinds", []),
                        "sink": finding.metadata.get("sink"),
                    },
                    0.8,
                )
            )

        cfg_path = finding.metadata.get("cfg_path")
        if isinstance(cfg_path, list) and cfg_path:
            items.append(
                self._evidence(
                    task,
                    EvidenceType.CFG_PATH,
                    "Normalized control-flow path from function entry to the detected sink.",
                    {
                        "finding_id": finding.vulnerability_id,
                        "path": cfg_path,
                        "sink": finding.metadata.get("sink"),
                    },
                    0.8,
                )
            )

        rule_id = finding.metadata.get("rule_id")
        if rule_id:
            items.append(
                self._evidence(
                    task,
                    EvidenceType.TOOL_RESULT,
                    "Deterministic source-audit rule metadata.",
                    {
                        "finding_id": finding.vulnerability_id,
                        "rule_id": rule_id,
                        "category": finding.metadata.get("category"),
                        "engine": finding.metadata.get("analysis_engine"),
                    },
                    0.8,
                )
            )
        return items

    def _evidence(
        self,
        task: Task,
        evidence_type: EvidenceType,
        description: str,
        data: dict[str, Any],
        reliability: float,
    ) -> Evidence:
        return Evidence(
            evidence_id=new_evidence_id(),
            task_id=task.task_id,
            evidence_type=evidence_type,
            source=self.name,
            description=description,
            data=data,
            reliability=reliability,
            created_by=self.name,
        )
