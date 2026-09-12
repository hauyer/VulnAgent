"""Specialized agent for protected-program restoration planning and evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import (
    AgentMessage,
    AgentMessageType,
    AgentResult,
    AnalysisContext,
    BinaryAnalysisRequest,
    Evidence,
    EvidenceType,
    Task,
)
from vulnagent.utils.ids import new_evidence_id, new_message_id


class RestorationCapability(Protocol):
    async def restore(
        self,
        request: BinaryAnalysisRequest,
        *,
        authorized: bool = False,
        dynamic_authorized: bool = False,
        emulator_serial: str | None = None,
    ) -> dict[str, Any]: ...


class ProgramRestorationAgent(BaseAgent):
    """Choose a bounded restoration strategy and preserve every stage as evidence."""

    name = "program_restoration"

    def __init__(self, engine: RestorationCapability) -> None:
        self.engine = engine

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        metadata = task.target.metadata if isinstance(task.target.metadata, Mapping) else {}
        try:
            result = await self.engine.restore(
                BinaryAnalysisRequest(
                    task_id=task.task_id,
                    target_id=task.target.target_id,
                    path=task.target.path,
                ),
                authorized=metadata.get("authorization_confirmed") is True,
                dynamic_authorized=(
                    metadata.get("dynamic_restoration_authorized") is True
                    and metadata.get("dynamic_validation") is True
                ),
                emulator_serial=(str(metadata["emulator_serial"]) if metadata.get("emulator_serial") else None),
            )
        except Exception as exc:
            # Restoration is a preparatory stage. Preserve a typed, auditable
            # failure and let the ordinary binary analyzer retain its own
            # independent fallback path.
            result = {
                "schema_version": 1,
                "engine": "program-restoration-engine",
                "status": "failed",
                "success": False,
                "output_path": None,
                "output_paths": [],
                "protection": {"selected": None},
                "strategy": [],
                "records": [{"stage": "initial_analysis", "status": "failed", "error_type": type(exc).__name__}],
                "validation": {"parseable": False, "error_type": type(exc).__name__},
                "metrics": {"artifact_count": 0, "parseable": False},
                "safety": {
                    "authorization_confirmed": metadata.get("authorization_confirmed") is True,
                    "dynamic_authorized": False,
                    "host_process_execution": False,
                },
            }
        protection = result.get("protection")
        if isinstance(protection, dict):
            protection.setdefault("declared_protection", metadata.get("protection"))
        evidence = Evidence(
            evidence_id=new_evidence_id(),
            task_id=task.task_id,
            evidence_type=EvidenceType.TOOL_RESULT,
            source=self.name,
            description=(
                "Protected-program classification, selected restoration strategy, "
                "artifact lineage and parseability validation."
            ),
            artifact_path=result.get("output_path"),
            data=result,
            reliability=0.9 if result.get("success") else 0.75,
            created_by=self.name,
        )
        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="binary_analysis",
            message_type=AgentMessageType.ANALYSIS_RESULT,
            payload={
                "role": self.name,
                "status": result.get("status"),
                "output_path": result.get("output_path"),
                "protection": result.get("protection", {}),
                "validation": result.get("validation", {}),
            },
            evidence_ids=[evidence.evidence_id],
        )
        artifacts = [str(item) for item in result.get("output_paths", []) if item]
        return AgentResult(agent_name=self.name, messages=[message], evidence=[evidence], artifacts=artifacts)
