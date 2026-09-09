"""Independent mock verification agent."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Evidence, EvidenceType, Task, VerificationContext, VulnerabilityCandidate, VulnerabilityVerifier
from vulnagent.utils.ids import new_evidence_id, new_message_id


def _partition_duplicates(
    findings: list[VulnerabilityCandidate],
) -> tuple[list[VulnerabilityCandidate], list[VulnerabilityCandidate]]:
    """Keep the first candidate for each (target, kind, location); return the rest.

    Agents must not import from the capability packages (architecture guard), so this
    mirrors ``vulnagent.verification.duplicate`` semantics inline. Both files belong
    to the same owner (P7) and must stay consistent.
    """
    seen: set[tuple[str, str, str]] = set()
    unique: list[VulnerabilityCandidate] = []
    duplicates: list[VulnerabilityCandidate] = []
    for finding in findings:
        key = (finding.target_id, finding.vulnerability_type, str(finding.location))
        if key in seen:
            duplicates.append(finding)
        else:
            seen.add(key)
            unique.append(finding)
    return unique, duplicates


class VerificationAgent(BaseAgent):
    name = "verification"

    def __init__(self, verifier: VulnerabilityVerifier) -> None:
        self.verifier = verifier

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        # Work on deep copies so the original discovery candidates are never mutated.
        findings = [item.model_copy(deep=True) for item in context.findings]
        # Deduplication belongs to the verification boundary: a later duplicate must
        # not receive a second, independent verdict for the same reported location.
        findings, duplicates = _partition_duplicates(findings)
        verification_context = VerificationContext(task_id=task.task_id, evidence=context.evidence)
        verifications = [await self.verifier.verify(finding, verification_context) for finding in findings]
        statuses = {item.vulnerability_id: item.status for item in verifications}
        evidence: list[Evidence] = []
        # Evidence-first: every verified finding receives its own VERIFICATION_RESULT
        # evidence so a verdict can be traced back to its rationale and inputs.
        for finding, verdict in zip(findings, verifications):
            finding.status = statuses[finding.vulnerability_id]
            item = Evidence(
                evidence_id=new_evidence_id(),
                task_id=task.task_id,
                evidence_type=EvidenceType.VERIFICATION_RESULT,
                source=self.name,
                description=f"Independent verification verdict: {verdict.status.value}.",
                data={
                    "vulnerability_id": verdict.vulnerability_id,
                    "status": verdict.status.value,
                    "confidence": verdict.confidence,
                    "rationale": verdict.rationale,
                    "referenced_evidence_ids": verdict.evidence_ids,
                    "duplicate_count": len(duplicates),
                },
                reliability=0.5,
                created_by=self.name,
            )
            finding.evidence_ids.append(item.evidence_id)
            evidence.append(item)
        request_additional = any(item.metadata.get("request_additional_analysis", False) for item in verifications)
        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="reviewer",
            message_type=AgentMessageType.VERIFICATION_RESULT,
            payload={
                "statuses": {item.vulnerability_id: item.status.value for item in findings},
                "request_additional_analysis": request_additional,
                "deduplicated": len(duplicates),
            },
            evidence_ids=[item.evidence_id for item in evidence],
        )
        return AgentResult(agent_name=self.name, messages=[message], findings=findings, evidence=evidence, verifications=verifications)
