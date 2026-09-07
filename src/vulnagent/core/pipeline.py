"""Sequential pipeline stage execution."""

from dataclasses import dataclass

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentResult, AnalysisContext, TaskStatus


@dataclass(frozen=True)
class PipelineStage:
    """Bind one lifecycle state to one agent."""

    status: TaskStatus
    agent: BaseAgent


class Pipeline:
    """Execute deterministic V0.1 stages and aggregate their results."""

    async def execute_stage(self, stage: PipelineStage, context: AnalysisContext) -> AgentResult:
        return await stage.agent.run(context.task, context)

    @staticmethod
    def merge(context: AnalysisContext, result: AgentResult, *, replace_findings: bool = False) -> None:
        context.messages.extend(result.messages)
        if replace_findings:
            context.findings = result.findings
        else:
            context.findings.extend(result.findings)
        context.evidence.extend(result.evidence)
        context.verifications.extend(result.verifications)
        context.reports.extend(result.reports)
        context.artifacts.extend(result.artifacts)
