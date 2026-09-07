"""Safe mock binary analysis agent that never executes binaries."""

from vulnagent.agents.base import BaseAgent
from vulnagent.core.models import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Task, VulnerabilityCandidate, VulnerabilityLocation
from vulnagent.utils.ids import new_message_id, new_vulnerability_id


class BinaryAnalysisAgent(BaseAgent):
    name = "binary_analysis"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        finding = VulnerabilityCandidate(vulnerability_id=new_vulnerability_id(), task_id=task.task_id, title="Mock suspicious binary pattern", vulnerability_type="mock_binary_finding", description="Synthetic V0.1 binary finding; the target was not opened or executed.", target_id=task.target.target_id, location=VulnerabilityLocation(module_name=task.target.path), source_agent=self.name, confidence=0.4, severity="INFO", metadata={"mock": True, "executed": False})
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, receiver="verification", message_type=AgentMessageType.VULNERABILITY_CANDIDATE, payload={"vulnerability_id": finding.vulnerability_id, "mock": True})
        return AgentResult(agent_name=self.name, messages=[message], findings=[finding])

