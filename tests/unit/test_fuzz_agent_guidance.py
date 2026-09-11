"""FuzzAgent translates prior candidates into structured guidance."""

from pathlib import Path

import pytest

from vulnagent.agents.fuzz_agent import FuzzAgent
from vulnagent.contracts import (
    AnalysisContext,
    FuzzRequest,
    FuzzResult,
    Target,
    TargetType,
    Task,
    VulnerabilityCandidate,
)


class CapturingEngine:
    def __init__(self) -> None:
        self.request: FuzzRequest | None = None

    async def run(self, request: FuzzRequest) -> FuzzResult:
        self.request = request
        return FuzzResult(task_id=request.task_id, target_id=request.target_id)


@pytest.mark.asyncio
async def test_agent_forwards_only_structured_bounded_risk_hints(
    tmp_path: Path,
) -> None:
    task = Task(
        task_id="guided-task",
        target=Target(
            target_id="target",
            path=str(tmp_path / "target.py"),
            target_type=TargetType.SOURCE,
            metadata={"fuzz_authorized": True},
        ),
    )
    finding = VulnerabilityCandidate(
        vulnerability_id="finding-1",
        task_id=task.task_id,
        title="Dynamic execution",
        vulnerability_type="dynamic_code_execution",
        cwe_id="CWE-95",
        description="candidate",
        target_id=task.target.target_id,
        source_agent="source_audit",
        confidence=0.8,
        metadata={"sink": "eval", "snippet": "must not be forwarded"},
    )
    engine = CapturingEngine()

    await FuzzAgent(engine).run(
        task,
        AnalysisContext(task=task, findings=[finding]),
    )

    assert engine.request is not None
    assert engine.request.metadata["risk_hints"] == [
        {
            "vulnerability_type": "dynamic_code_execution",
            "cwe_id": "CWE-95",
            "sink": "eval",
            "confidence": 0.8,
        }
    ]
    assert engine.request.metadata["guidance_source_finding_ids"] == ["finding-1"]
    assert "snippet" not in engine.request.metadata["risk_hints"][0]
