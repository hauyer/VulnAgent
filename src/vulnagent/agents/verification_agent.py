"""Independent mock verification agent."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Evidence, EvidenceType, Task, VerificationContext, VulnerabilityVerifier
from vulnagent.utils.ids import new_evidence_id, new_message_id


class VerificationAgent(BaseAgent):
    name = "verification"

    def __init__(self, verifier: VulnerabilityVerifier) -> None:
        self.verifier = verifier

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        findings = [item.model_copy(deep=True) for item in context.findings]
        verification_context = VerificationContext(task_id=task.task_id, evidence=context.evidence)
        verifications = [await self.verifier.verify(finding, verification_context) for finding in findings]
        statuses = {item.vulnerability_id: item.status for item in verifications}
        for finding in findings:
            finding.status = statuses[finding.vulnerability_id]
        evidence = Evidence(evidence_id=new_evidence_id(), task_id=task.task_id, evidence_type=EvidenceType.VERIFICATION_RESULT, source=self.name, description="Independent mock verification completed; synthetic findings remain uncertain.", data={"mock": True, "finding_ids": [item.vulnerability_id for item in findings]}, reliability=0.5, created_by=self.name)
        for finding in findings:
            finding.evidence_ids.append(evidence.evidence_id)
        request_additional = any(item.metadata.get("request_additional_analysis", False) for item in verifications)
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, receiver="reviewer", message_type=AgentMessageType.VERIFICATION_RESULT, payload={"statuses": {item.vulnerability_id: item.status.value for item in findings}, "request_additional_analysis": request_additional, "mock": True}, evidence_ids=[evidence.evidence_id])
        return AgentResult(agent_name=self.name, messages=[message], findings=findings, evidence=[evidence], verifications=verifications)
