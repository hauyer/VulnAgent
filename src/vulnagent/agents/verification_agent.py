"""Independent verification agent (P7).

Single-source canonicalization: duplicate candidates are merged into a canonical
candidate with fused evidence and traceable ``metadata["duplicate_ids"]``, never
silently deleted.  Each canonical candidate is then handed to the injected
``VulnerabilityVerifier`` for an independent verdict, and every verdict is
recorded as its own ``VERIFICATION_RESULT`` Evidence for traceability.

Note on architecture: the agent must not import the capability packages
(architecture guard), so the canonicalization logic lives here as the single
source of truth.
"""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Evidence, EvidenceType, Task, VerificationContext, VulnerabilityCandidate, VulnerabilityVerifier
from vulnagent.utils.ids import new_evidence_id, new_message_id


def _has_reliable_location(finding: VulnerabilityCandidate) -> bool:
    """A location is merge-reliable only when it carries an actual locator."""
    location = finding.location
    return location is not None and bool(
        location.file_path or location.binary_address or location.module_name
    )


def canonicalize_candidates(
    findings: list[VulnerabilityCandidate],
) -> tuple[list[VulnerabilityCandidate], int]:
    """Merge exact duplicates into canonical candidates.

    Rules:
      * Only candidates sharing ``(target_id, vulnerability_type)`` **and** a
        reliable location are treated as the same finding.
      * A candidate without a reliable location is never collapsed through a
        bare ``None`` key -- each stays independent.
      * The first candidate of a group stays canonical; evidence ids are fused
        (sorted union) and merged-away ids are recorded in
        ``metadata["duplicate_ids"]`` so nothing is silently dropped.

    Returns ``(canonical_findings, merged_count)``.  Input is treated as deep
    copies by the caller; only canonical copies are mutated for the merge.
    """
    canonicals: dict[tuple[str, str, str], VulnerabilityCandidate] = {}
    merged_count = 0
    for finding in findings:
        if _has_reliable_location(finding):
            key = (finding.target_id, finding.vulnerability_type, str(finding.location))
        else:
            # No reliable location -> never merge with others.
            key = (finding.target_id, finding.vulnerability_type, finding.vulnerability_id)

        existing = canonicals.get(key)
        if existing is None:
            canonicals[key] = finding
            continue
        if finding.vulnerability_id == existing.vulnerability_id:
            # The exact same candidate reported twice; count it but keep one copy.
            merged_count += 1
            continue

        # Duplicate with a distinct id: fuse its evidence into the canonical.
        existing.evidence_ids = sorted(set(existing.evidence_ids) | set(finding.evidence_ids))
        duplicate_ids = set(existing.metadata.get("duplicate_ids", []))
        duplicate_ids.add(finding.vulnerability_id)
        existing.metadata["duplicate_ids"] = sorted(duplicate_ids)
        merged_count += 1

    return list(canonicals.values()), merged_count


class VerificationAgent(BaseAgent):
    name = "verification"

    def __init__(self, verifier: VulnerabilityVerifier) -> None:
        self.verifier = verifier

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        # Work on deep copies so the original discovery candidates are never mutated.
        findings = [item.model_copy(deep=True) for item in context.findings]
        contextual_evidence: dict[str, list[str]] = {}
        for item in context.evidence:
            finding_id = item.data.get("finding_id") or item.data.get("vulnerability_id")
            if isinstance(finding_id, str):
                contextual_evidence.setdefault(finding_id, []).append(item.evidence_id)
        for finding in findings:
            finding.evidence_ids = sorted(
                set(finding.evidence_ids)
                | set(contextual_evidence.get(finding.vulnerability_id, []))
            )
        # Canonicalization is part of the verification boundary: exact duplicates
        # are merged (evidence fused, ids traced) before an independent verdict.
        findings, merged_count = canonicalize_candidates(findings)

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
                    "duplicate_ids": finding.metadata.get("duplicate_ids", []),
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
                "merged": merged_count,
            },
            evidence_ids=[item.evidence_id for item in evidence],
        )
        return AgentResult(agent_name=self.name, messages=[message], findings=findings, evidence=evidence, verifications=verifications)
