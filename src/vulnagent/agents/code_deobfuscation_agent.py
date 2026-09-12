"""Specialized agent for deterministic and LLM-assisted semantic recovery."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import (
    AgentMessage,
    AgentMessageType,
    AgentResult,
    AnalysisContext,
    BinaryAnalysisResult,
    Evidence,
    EvidenceType,
    Task,
)
from vulnagent.utils.ids import new_evidence_id, new_message_id


class DeobfuscationCapability(Protocol):
    async def restore(self, result: BinaryAnalysisResult) -> dict[str, Any]: ...


class SemanticEnhancer(Protocol):
    async def enhance(self, recovery: dict[str, Any]) -> dict[str, Any]: ...


class CodeDeobfuscationAgent(BaseAgent):
    """Recover auditable structure while keeping model output non-authoritative."""

    name = "code_deobfuscation"

    def __init__(self, engine: DeobfuscationCapability, enhancer: SemanticEnhancer | None = None) -> None:
        self.engine = engine
        self.enhancer = enhancer

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        analysis = self._latest_analysis(context)
        if analysis is None:
            recovery = {
                "schema_version": 1,
                "engine": "static-ollvm-deobfuscation",
                "status": "no_binary_analysis",
                "detected_types": [],
                "readability": {"before": 0, "after": 0, "improvement": 0},
            }
        else:
            recovery = await self.engine.restore(analysis)
            recovery["status"] = "completed"

        semantic = (
            await self.enhancer.enhance(recovery)
            if self.enhancer is not None
            else {"used": False, "status": "not_configured", "annotations": []}
        )
        deterministic = Evidence(
            evidence_id=new_evidence_id(),
            task_id=task.task_id,
            evidence_type=EvidenceType.TOOL_RESULT,
            source=self.name,
            description="Deterministic OLLVM-pattern recovery with before/after pseudocode and CFG evidence.",
            data=recovery,
            reliability=0.82,
            created_by=self.name,
        )
        evidence = [deterministic]
        if semantic.get("used"):
            evidence.append(Evidence(
                evidence_id=new_evidence_id(),
                task_id=task.task_id,
                evidence_type=EvidenceType.MODEL_REASONING_SUMMARY,
                source="semantic_recovery",
                description="Model-assisted business-logic annotations; auxiliary evidence only.",
                data=semantic,
                reliability=0.55,
                created_by=self.name,
            ))
        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="verification",
            message_type=AgentMessageType.ANALYSIS_RESULT,
            payload={
                "role": self.name,
                "detected_types": recovery.get("detected_types", []),
                "readability": recovery.get("readability", {}),
                "semantic_status": semantic.get("status"),
            },
            evidence_ids=[item.evidence_id for item in evidence],
        )
        return AgentResult(agent_name=self.name, messages=[message], evidence=evidence)

    @staticmethod
    def _latest_analysis(context: AnalysisContext) -> BinaryAnalysisResult | None:
        for message in reversed(context.messages):
            if message.sender != "binary_analysis":
                continue
            raw = message.payload.get("analysis")
            if not isinstance(raw, Mapping):
                continue
            derived = raw.get("metadata", {}).get("unpacked_analysis") if isinstance(raw.get("metadata"), Mapping) else None
            try:
                return BinaryAnalysisResult.model_validate(dict(derived if isinstance(derived, Mapping) else raw))
            except Exception:
                continue
        return None
