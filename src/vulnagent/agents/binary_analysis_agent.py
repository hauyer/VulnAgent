"""Static binary analysis agent; target binaries are never executed."""

import asyncio
import re
from typing import Any

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import (
    AgentMessage,
    AgentMessageType,
    AgentResult,
    AnalysisContext,
    BinaryAnalysisRequest,
    BinaryAnalyzer,
    BinaryFeatureAnalyzer,
    Evidence,
    EvidenceType,
    Task,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)
from vulnagent.utils.ids import new_evidence_id, new_message_id, new_vulnerability_id


RISKY_SYMBOLS = frozenset(
    {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "system", "popen", "scanf"}
)
_SYMBOL_TOKEN = re.compile(r"[a-z0-9_@?]+")
_KNOWN_SYMBOL_PREFIXES = ("__imp_", "_imp__", "ucrt_")


class BinaryAnalysisAgent(BaseAgent):
    """Coordinate a bounded static analyzer and normalize concrete signals."""

    name = "binary_analysis"

    def __init__(
        self,
        analyzer: BinaryAnalyzer,
        logic_analyzer: BinaryFeatureAnalyzer | None = None,
        obfuscation_analyzer: BinaryFeatureAnalyzer | None = None,
    ) -> None:
        self.analyzer = analyzer
        self.logic_analyzer = logic_analyzer
        self.obfuscation_analyzer = obfuscation_analyzer

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        analysis = await self.analyzer.analyze(
            BinaryAnalysisRequest(
                task_id=task.task_id,
                target_id=task.target.target_id,
                path=task.target.path,
            )
        )
        logic, obfuscation = await asyncio.gather(
            self._inspect_feature(self.logic_analyzer, analysis, "binary.logic"),
            self._inspect_feature(
                self.obfuscation_analyzer,
                analysis,
                "binary.obfuscation",
            ),
        )
        is_mock = bool(analysis.metadata.get("mock"))
        matched = self._risky_symbols(analysis.imports, analysis.strings)
        semantic_callsites = self._risky_callsites(analysis.metadata)
        matched = sorted(
            set(matched).union(
                str(item["inferred_api"])
                for item in semantic_callsites
                if item.get("inferred_api")
            )
        )
        evidence = self._feature_evidence(task.task_id, logic, obfuscation)
        findings: list[VulnerabilityCandidate] = []

        if is_mock:
            matched = ["mock-signal"]

        if matched:
            semantic_only = bool(semantic_callsites)
            signal = Evidence(
                evidence_id=new_evidence_id(),
                task_id=task.task_id,
                evidence_type=(
                    EvidenceType.DISASSEMBLY
                    if semantic_only and not is_mock
                    else EvidenceType.BINARY_ADDRESS
                ),
                source=self.name,
                description=(
                    "Synthetic binary location from the mock analyzer."
                    if is_mock
                    else (
                        "Bounded call-site decoding inferred an unbounded format write "
                        "from the runtime helper argument shape."
                        if semantic_only
                        else "Static binary inspection located a risky imported or embedded symbol."
                    )
                ),
                data={
                    "path": analysis.path,
                    "file_format": analysis.file_format,
                    "architecture": analysis.architecture,
                    "matched_symbols": matched,
                    "semantic_callsites": semantic_callsites,
                    "signal_basis": (
                        "pe_x64_callsite_semantics"
                        if semantic_only
                        else "explicit_symbol"
                    ),
                    "sha256": analysis.metadata.get("sha256"),
                    "executed": False,
                    "mock": is_mock,
                },
                reliability=0.4 if is_mock else (0.85 if semantic_only else 0.75),
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
                    else (
                        "A bounded static inspection inferred an unbounded format-write "
                        "wrapper from a call-site argument sentinel. This local signal "
                        "does not prove reachability or exploitability and requires verification."
                        if semantic_only
                        else "A bounded static inspection found a risky API symbol. "
                        "This signal alone does not prove reachability and requires verification."
                    )
                ),
                target_id=task.target.target_id,
                location=VulnerabilityLocation(module_name=task.target.path),
                source_agent=self.name,
                source_type="binary",
                producer=type(self.analyzer).__name__,
                confidence=0.4 if is_mock else (0.72 if semantic_only else 0.65),
                severity="INFO" if is_mock else "MEDIUM",
                evidence_ids=[signal.evidence_id],
                metadata={
                    "mock": is_mock,
                    "executed": False,
                    "matched_symbols": matched,
                    "semantic_callsite_count": len(semantic_callsites),
                    "signal_basis": (
                        "pe_x64_callsite_semantics"
                        if semantic_only
                        else "explicit_symbol"
                    ),
                    "logic_categories": sorted(logic.get("summary", {})),
                    "obfuscation_score": obfuscation.get("score", 0),
                },
            )
            finding.evidence_ids.extend(
                item.evidence_id for item in evidence if item.evidence_id != signal.evidence_id
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
                "feature_analysis": {
                    "logic": logic,
                    "obfuscation": obfuscation,
                },
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
    async def _inspect_feature(
        analyzer: BinaryFeatureAnalyzer | None,
        analysis: Any,
        capability: str,
    ) -> dict[str, Any]:
        """Run one optional feature analyzer with a public, bounded failure result."""
        if analyzer is None:
            return {"available": False, "capability": capability}
        try:
            result = await analyzer.inspect(analysis)
        except Exception as exc:  # feature failure must not discard reverse facts
            return {
                "available": True,
                "capability": capability,
                "error_type": type(exc).__name__,
            }
        return {"available": True, "capability": capability, **result}

    @staticmethod
    def _feature_evidence(
        task_id: str,
        logic: dict[str, Any],
        obfuscation: dict[str, Any],
    ) -> list[Evidence]:
        """Convert semantic feature results into auxiliary, traceable evidence."""
        evidence: list[Evidence] = []
        locations = logic.get("locations")
        if isinstance(locations, list) and locations:
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=task_id,
                    evidence_type=EvidenceType.TOOL_RESULT,
                    source="binary_logic",
                    description=(
                        "High-value binary logic was localized from previously "
                        "extracted facts; these clues are not a vulnerability verdict."
                    ),
                    data={
                        "summary": logic.get("summary", {}),
                        "locations": locations,
                    },
                    reliability=0.7,
                    created_by="binary_analysis",
                )
            )

        signals = obfuscation.get("signals")
        score = obfuscation.get("score", 0)
        if (isinstance(signals, list) and signals) or (
            isinstance(score, (int, float)) and score > 0
        ):
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=task_id,
                    evidence_type=EvidenceType.TOOL_RESULT,
                    source="binary_obfuscation",
                    description=(
                        "Packing or obfuscation heuristics were scored from static "
                        "facts; the score is an analysis hint, not a final verdict."
                    ),
                    data={
                        "score": score,
                        "base_score": obfuscation.get("base_score", 0),
                        "signals": signals if isinstance(signals, list) else [],
                    },
                    reliability=0.7,
                    created_by="binary_analysis",
                )
            )
        return evidence

    @staticmethod
    def _risky_symbols(imports: list[str], strings: list[str]) -> list[str]:
        """Return explicit risky symbols without substring-only false matches.

        Some C runtimes route both bounded ``snprintf`` and unbounded
        ``sprintf`` through an internal ``__stdio_common_vsprintf`` helper.
        That helper is therefore deliberately not treated as a vulnerability
        signal.  Exact or recognizably decorated public symbol names are
        retained; ambiguous runtime implementation details remain available to
        the logic analyzer as auxiliary evidence.
        """
        matches: set[str] = set()
        for value in [*imports, *strings]:
            for token in _SYMBOL_TOKEN.findall(str(value).casefold()):
                variants = {token, token.lstrip("_").split("@", 1)[0]}
                pending = list(variants)
                for variant in pending:
                    for prefix in _KNOWN_SYMBOL_PREFIXES:
                        if variant.startswith(prefix):
                            variants.add(variant.removeprefix(prefix))
                matches.update(RISKY_SYMBOLS.intersection(variants))
        return sorted(matches)

    @staticmethod
    def _risky_callsites(metadata: dict[str, Any]) -> list[dict[str, Any]]:
        """Select high-confidence, non-executing call-site risk facts.

        The structural analyzer owns decoding and provenance.  This Agent only
        accepts the narrow, versioned classification for an unbounded UCRT
        format-write shape; bounded or unknown helper calls remain auxiliary
        facts and cannot become findings here.
        """
        semantics = metadata.get("callsite_semantics")
        if not isinstance(semantics, dict):
            return []
        if (
            semantics.get("schema_version") != 1
            or semantics.get("analyzer") != "pe-x64-callsite-semantics"
            or semantics.get("available") is not True
            or semantics.get("target_executed") is not False
        ):
            return []
        callsites = semantics.get("callsites")
        if not isinstance(callsites, list):
            return []
        return [
            dict(item)
            for item in callsites
            if isinstance(item, dict)
            and item.get("classification") == "unbounded_format_write"
            and item.get("inferred_api") == "sprintf"
            and isinstance(item.get("confidence"), (int, float))
            and not isinstance(item.get("confidence"), bool)
            and float(item["confidence"]) >= 0.85
        ]
