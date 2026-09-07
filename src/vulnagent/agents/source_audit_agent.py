"""Safe mock source audit agent."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, ProjectInput, SourceAuditor, SourceParser, Task
from vulnagent.utils.ids import new_message_id


class SourceAuditAgent(BaseAgent):
    name = "source_audit"

    def __init__(self, parser: SourceParser, auditor: SourceAuditor) -> None:
        self.parser = parser
        self.auditor = auditor

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        parsed = await self.parser.analyze(ProjectInput(task_id=task.task_id, target_id=task.target.target_id, project_path=task.target.path))
        findings = await self.auditor.audit(parsed)
        finding = findings[0]
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, receiver="verification", message_type=AgentMessageType.VULNERABILITY_CANDIDATE, payload={"vulnerability_id": finding.vulnerability_id, "mock": True})
        return AgentResult(agent_name=self.name, messages=[message], findings=findings)
