"""Independent mock verification agent."""

from vulnagent.agents.base import BaseAgent
from vulnagent.core.models import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Evidence, EvidenceType, Task, VulnerabilityStatus
from vulnagent.utils.ids import new_evidence_id, new_message_id


class VerificationAgent(BaseAgent):
    name = "verification"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        findings = [item.model_copy(deep=True) for item in context.findings]
        for finding in findings:
            finding.status = VulnerabilityStatus.UNCERTAIN if finding.metadata.get("mock") else VulnerabilityStatus.REJECTED
        evidence = Evidence(evidence_id=new_evidence_id(), task_id=task.task_id, evidence_type=EvidenceType.VERIFICATION_RESULT, source=self.name, description="Independent mock verification completed; synthetic findings remain uncertain.", data={"mock": True, "finding_ids": [item.vulnerability_id for item in findings]}, reliability=0.5, created_by=self.name)
        for finding in findings:
            finding.evidence_ids.append(evidence.evidence_id)
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, receiver="reviewer", message_type=AgentMessageType.VERIFICATION_RESULT, payload={"statuses": {item.vulnerability_id: item.status.value for item in findings}, "mock": True}, evidence_ids=[evidence.evidence_id])
        return AgentResult(agent_name=self.name, messages=[message], findings=findings, evidence=[evidence])

