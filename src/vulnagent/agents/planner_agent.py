"""Mock planning agent."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, TargetType, Task
from vulnagent.utils.ids import new_message_id


class PlannerAgent(BaseAgent):
    name = "planner"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        analyzer = "binary_analysis" if task.target.target_type is TargetType.BINARY else "source_audit"
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, receiver=analyzer, message_type=AgentMessageType.PLAN, payload={"steps": [analyzer, "fuzz", "verification", "reviewer", "report"], "mock": True})
        return AgentResult(agent_name=self.name, messages=[message])
