"""Static binary analysis agent; target binaries are never executed."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import (
    AgentMessage,
    AgentMessageType,
    AgentResult,
    AnalysisContext,
    BinaryAnalysisRequest,
    BinaryAnalyzer,
    Evidence,
    EvidenceType,
    Task,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)
from vulnagent.utils.ids import new_evidence_id, new_message_id, new_vulnerability_id


RISKY_SYMBOLS = frozenset(
    {"gets", "strcpy", "strcat", "sprintf", "system", "popen", "scanf"}
)


class BinaryAnalysisAgent(BaseAgent):
    """Coordinate a bounded static analyzer and normalize concrete signals."""

    name = "binary_analysis"

    def __init__(self, analyzer: BinaryAnalyzer) -> None:
        self.analyzer = analyzer

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        analysis = await self.analyzer.analyze(
            BinaryAnalysisRequest(
                task_id=task.task_id,
                target_id=task.target.target_id,
                path=task.target.path,
            )
        )
        is_mock = bool(analysis.metadata.get("mock"))
        matched = self._risky_symbols(analysis.imports, analysis.strings)
        evidence: list[Evidence] = []
        findings: list[VulnerabilityCandidate] = []

        if is_mock:
            matched = ["mock-signal"]

        if matched:
            signal = Evidence(
                evidence_id=new_evidence_id(),
                task_id=task.task_id,
                evidence_type=EvidenceType.BINARY_ADDRESS,
                source=self.name,
                description=(
                    "Synthetic binary location from the mock analyzer."
                    if is_mock
                    else "Static binary inspection located a risky imported or embedded symbol."
                ),
                data={
                    "path": analysis.path,
                    "file_format": analysis.file_format,
                    "architecture": analysis.architecture,
                    "matched_symbols": matched,
                    "sha256": analysis.metadata.get("sha256"),
                    "executed": False,
                    "mock": is_mock,
                },
                reliability=0.4 if is_mock else 0.75,
                created_by=self.name,
            )
            evidence.append(signal)
            finding = VulnerabilityCandidate(
                vulnerability_id=new_vulnerability_id(),
                task_id=task.task_id,
                title=(
                    "Mock suspicious binary pattern"
                    if is_mock
                    else "Risky API symbol present in binary"
                ),
                vulnerability_type=(
                    "mock_binary_finding" if is_mock else "risky_binary_api"
                ),
                description=(
                    "Synthetic V0.2 binary finding; the target was not opened or executed."
                    if is_mock
                    else "A bounded static inspection found a risky API symbol. "
                    "This signal alone does not prove reachability and requires verification."
                ),
                target_id=task.target.target_id,
                location=VulnerabilityLocation(module_name=task.target.path),
                source_agent=self.name,
                source_type="binary",
                producer=type(self.analyzer).__name__,
                confidence=0.4 if is_mock else 0.65,
                severity="INFO" if is_mock else "MEDIUM",
                evidence_ids=[signal.evidence_id],
                metadata={"mock": is_mock, "executed": False, "matched_symbols": matched},
            )
            findings.append(finding)

        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="verification",
            message_type=(
                AgentMessageType.VULNERABILITY_CANDIDATE
                if findings
                else AgentMessageType.ANALYSIS_RESULT
            ),
            payload={
                "finding_ids": [item.vulnerability_id for item in findings],
                "analysis": analysis.model_dump(mode="json"),
                "mock": is_mock,
            },
            evidence_ids=[item.evidence_id for item in evidence],
        )
        return AgentResult(
            agent_name=self.name,
            messages=[message],
            findings=findings,
            evidence=evidence,
        )

    @staticmethod
    def _risky_symbols(imports: list[str], strings: list[str]) -> list[str]:
        matches: set[str] = set()
        for value in [*imports, *strings]:
            lowered = str(value).casefold()
            for symbol in RISKY_SYMBOLS:
                if symbol in lowered:
                    matches.add(symbol)
        return sorted(matches)
