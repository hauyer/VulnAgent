"""Authorization-gated fuzz agent and crash-candidate adapter."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import (
    AgentMessage,
    AgentMessageType,
    AgentResult,
    AnalysisContext,
    Evidence,
    EvidenceType,
    FuzzEngine,
    FuzzRequest,
    Task,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)
from vulnagent.utils.ids import new_evidence_id, new_message_id, new_vulnerability_id


class FuzzAgent(BaseAgent):
    """Invoke the fuzz port and turn real crash evidence into candidates."""

    name = "fuzz"

    def __init__(self, engine: FuzzEngine) -> None:
        self.engine = engine

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        authorized = bool(task.target.metadata.get("fuzz_authorized", False))
        risk_hints, source_finding_ids = self._risk_guidance(context)
        result = await self.engine.run(
            FuzzRequest(
                task_id=task.task_id,
                target_id=task.target.target_id,
                target_path=task.target.path,
                authorized=authorized,
                metadata={
                    "seed_dir": task.target.metadata.get("seed_dir"),
                    "risk_hints": risk_hints,
                    "guidance_source_finding_ids": source_finding_ids,
                },
            )
        )
        evidence = list(result.evidence)
        is_mock = bool(result.metadata.get("mock"))
        if not evidence:
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=task.task_id,
                    evidence_type=EvidenceType.TOOL_RESULT,
                    source="mock_fuzzer" if is_mock else "controlled_fuzzer",
                    description=(
                        "Mock fuzz stage completed without executing the target."
                        if is_mock
                        else "Fuzz stage did not execute the target."
                    ),
                    data={
                        "mock": is_mock,
                        "authorized": authorized,
                        "executed": result.executed,
                        "crashes": result.crashes,
                        "reason": result.metadata.get("reason"),
                    },
                    reliability=0.3,
                    created_by=self.name,
                )
            )

        crash_ids = [
            item.evidence_id
            for item in evidence
            if item.evidence_type is EvidenceType.CRASH_LOG
        ]
        findings: list[VulnerabilityCandidate] = []
        if result.executed and crash_ids:
            findings.append(
                VulnerabilityCandidate(
                    vulnerability_id=new_vulnerability_id(),
                    task_id=task.task_id,
                    title="Controlled fuzz execution detected an abnormal exit",
                    vulnerability_type="fuzz_crash",
                    cwe_id=None,
                    description=(
                        "A local, explicitly authorized fuzz run produced a "
                        "reproducible crash signature requiring independent review."
                    ),
                    target_id=task.target.target_id,
                    location=VulnerabilityLocation(module_name=task.target.path),
                    source_agent=self.name,
                    source_type="dynamic",
                    producer=type(self.engine).__name__,
                    confidence=0.9,
                    severity="HIGH",
                    evidence_ids=crash_ids,
                    metadata={
                        "mock": False,
                        "authorized": True,
                        "executions": result.metadata.get("executions", 0),
                        "mutation_strategy": result.metadata.get(
                            "mutation_strategy",
                            "generic",
                        ),
                        "guidance_risk_types": result.metadata.get(
                            "guidance_risk_types",
                            [],
                        ),
                    },
                )
            )

        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="verification",
            message_type=AgentMessageType.FUZZ_RESULT,
            payload=result.model_dump(mode="json", exclude={"evidence"}),
            evidence_ids=[item.evidence_id for item in evidence],
        )
        return AgentResult(
            agent_name=self.name,
            messages=[message],
            findings=findings,
            evidence=evidence,
        )

    @staticmethod
    def _risk_guidance(
        context: AnalysisContext,
    ) -> tuple[list[dict[str, object]], list[str]]:
        """Normalize prior candidates into bounded provider-neutral fuzz hints."""
        hints: list[dict[str, object]] = []
        finding_ids: list[str] = []
        seen: set[tuple[str, str | None, str | None]] = set()
        for finding in context.findings:
            if finding.source_agent == "fuzz":
                continue
            key = (
                finding.vulnerability_type,
                finding.cwe_id,
                str(finding.metadata.get("sink") or "") or None,
            )
            if key in seen:
                continue
            seen.add(key)
            hints.append(
                {
                    "vulnerability_type": key[0],
                    "cwe_id": key[1],
                    "sink": key[2],
                    "confidence": finding.confidence,
                }
            )
            finding_ids.append(finding.vulnerability_id)
            if len(hints) >= 16:
                break
        return hints, finding_ids
