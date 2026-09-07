"""Mock reviewer agent."""

from vulnagent.agents.base import BaseAgent
from vulnagent.core.models import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Task
from vulnagent.utils.ids import new_message_id


class ReviewerAgent(BaseAgent):
    name = "reviewer"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, receiver="report", message_type=AgentMessageType.REVIEW_RESULT, payload={"reviewed": len(context.findings), "mock": True})
        return AgentResult(agent_name=self.name, messages=[message])

