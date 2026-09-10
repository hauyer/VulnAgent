"""Structured report agent using the injected report capability."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, ReportGenerator, ReportRequest, Task
from vulnagent.utils.ids import new_message_id


class ReportAgent(BaseAgent):
    name = "report"

    def __init__(self, generator: ReportGenerator) -> None:
        self.generator = generator

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        report = await self.generator.generate(ReportRequest(task=task, findings=context.findings, evidence=context.evidence, verifications=context.verifications))
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, message_type=AgentMessageType.REPORT_RESULT, payload={"report": report.model_dump(mode="json")})
        return AgentResult(agent_name=self.name, messages=[message], reports=[report], artifacts=[report.artifact_uri] if report.artifact_uri else [])
