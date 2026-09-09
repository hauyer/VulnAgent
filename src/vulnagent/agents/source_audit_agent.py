"""Safe mock source audit agent."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Evidence, EvidenceType, ProjectInput, SourceAuditor, SourceParser, Task
from vulnagent.utils.ids import new_evidence_id, new_message_id


class SourceAuditAgent(BaseAgent):
    """Coordinate source capability protocols and normalize their evidence."""

    name = "source_audit"

    def __init__(self, parser: SourceParser, auditor: SourceAuditor) -> None:
        self.parser = parser
        self.auditor = auditor

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        parsed = await self.parser.analyze(ProjectInput(task_id=task.task_id, target_id=task.target.target_id, project_path=task.target.path))
        findings = await self.auditor.audit(parsed)
        evidence: list[Evidence] = []
        messages = [
            AgentMessage(
                message_id=new_message_id(),
                task_id=task.task_id,
                sender=self.name,
                receiver="supervisor",
                message_type=AgentMessageType.ANALYSIS_RESULT,
                payload={"finding_count": len(findings), "analysis": parsed.model_dump(mode="json"), "mock": True},
            )
        ]
        for finding in findings:
            item = Evidence(
                evidence_id=new_evidence_id(),
                task_id=task.task_id,
                evidence_type=EvidenceType.SOURCE_LOCATION,
                source=self.name,
                description="Source audit capability returned a candidate at the recorded location.",
                data={"location": finding.location.model_dump(mode="json") if finding.location else None, "mock": True},
                reliability=0.5,
                created_by=self.name,
            )
            finding.evidence_ids.append(item.evidence_id)
            evidence.append(item)
            messages.append(AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, receiver="verification", message_type=AgentMessageType.VULNERABILITY_CANDIDATE, payload={"vulnerability_id": finding.vulnerability_id, "mock": True}, evidence_ids=[item.evidence_id]))
        return AgentResult(agent_name=self.name, messages=messages, findings=findings, evidence=evidence)
