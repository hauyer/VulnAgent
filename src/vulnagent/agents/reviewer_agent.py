"""Independent structural reviewer agent."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Task
from vulnagent.utils.ids import new_message_id


class ReviewerAgent(BaseAgent):
    """Review verification consistency without changing finding status."""

    name = "reviewer"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        evidence_ids = {item.evidence_id for item in context.evidence}
        verification_by_id = {item.vulnerability_id: item for item in context.verifications}
        notes: list[str] = []
        seen: set[str] = set()
        for finding in context.findings:
            if finding.vulnerability_id in seen:
                notes.append(f"duplicate finding: {finding.vulnerability_id}")
            seen.add(finding.vulnerability_id)
            if not finding.evidence_ids or not set(finding.evidence_ids).intersection(evidence_ids):
                notes.append(f"missing evidence: {finding.vulnerability_id}")
            verification = verification_by_id.get(finding.vulnerability_id)
            if verification is None:
                notes.append(f"missing verification: {finding.vulnerability_id}")
            elif verification.status is not finding.status:
                notes.append(f"status mismatch: {finding.vulnerability_id}")
            if not 0.0 <= finding.confidence <= 1.0:
                notes.append(f"invalid confidence: {finding.vulnerability_id}")
            if not finding.title or not finding.description or not finding.source_agent:
                notes.append(f"missing required field: {finding.vulnerability_id}")
        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="report",
            message_type=AgentMessageType.REVIEW_RESULT,
            payload={"reviewed": len(context.findings), "review_passed": not notes, "review_notes": notes, "mock": True},
            evidence_ids=sorted(evidence_ids),
        )
        return AgentResult(agent_name=self.name, messages=[message])
