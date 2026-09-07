"""Mock structured report agent."""

from vulnagent.agents.base import BaseAgent
from vulnagent.core.models import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Task
from vulnagent.utils.ids import new_message_id


class ReportAgent(BaseAgent):
    name = "report"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        report = {"task_id": task.task_id, "target_id": task.target.target_id, "finding_count": len(context.findings), "evidence_count": len(context.evidence), "mock": True}
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, message_type=AgentMessageType.REPORT_RESULT, payload={"report": report})
        return AgentResult(agent_name=self.name, messages=[message], artifacts=[f"memory://reports/{task.task_id}"])
