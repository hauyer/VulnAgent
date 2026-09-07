"""Safe mock source audit agent."""

from vulnagent.agents.base import BaseAgent
from vulnagent.core.models import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Task, VulnerabilityCandidate, VulnerabilityLocation
from vulnagent.utils.ids import new_message_id, new_vulnerability_id


class SourceAuditAgent(BaseAgent):
    name = "source_audit"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        finding = VulnerabilityCandidate(vulnerability_id=new_vulnerability_id(), task_id=task.task_id, title="Mock unsafe input handling", vulnerability_type="mock_source_finding", cwe_id=None, description="Synthetic V0.1 source finding; no source code was scanned.", target_id=task.target.target_id, location=VulnerabilityLocation(file_path=task.target.path), source_agent=self.name, confidence=0.5, severity="INFO", metadata={"mock": True})
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, receiver="verification", message_type=AgentMessageType.VULNERABILITY_CANDIDATE, payload={"vulnerability_id": finding.vulnerability_id, "mock": True})
        return AgentResult(agent_name=self.name, messages=[message], findings=[finding])

