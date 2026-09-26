"""S1: formal AgentRuntime benchmark entry for blind discovery.

Drives a blind discovery run through the actual V0.2 AgentRuntime (LangGraph
state graph, Supervisor, Router, bounded steps) instead of calling the runner
directly.  The registered agent set is:

* ``planner``            - deterministic structured plan (no LLM advisory).
* ``binary_analysis``    - BlindBinaryObserverAgent: static observation only.
* ``fuzz``               - BlindDiscoveryAgent: the bounded discovery loop.
* ``verification``       - VerificationAgent over an injectable verifier.
* ``reviewer`` / ``report`` - V0.2 independent review + report nodes.

Only the de-identified AgentTargetSpec facts enter the Task metadata; the
runtime never sees ground truth.  The full AgentMessage / DomainEvent /
route history is dumped as ``agent_trace.jsonl`` for the trace audit.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from vulnagent.agent_runtime import AgentRuntime, RuntimePolicy, Supervisor
from vulnagent.agents import (
    BlindBinaryObserverAgent,
    BlindDiscoveryAgent,
    PlannerAgent,
    ReportAgent,
    ReviewerAgent,
    VerificationAgent,
)
from vulnagent.agents.base import BaseAgent
from vulnagent.agents.registry import AgentRegistry
from vulnagent.benchmark.discovery_ports import AgentTargetSpec
from vulnagent.contracts import (
    AgentResult,
    AnalysisContext,
    Target,
    TargetType,
    Task,
    VulnerabilityVerifier,
)
from vulnagent.report.generator import MockReportGenerator
from vulnagent.verification.verifier import MockVerifier


class NoopSourceAgent(BaseAgent):
    """Placeholder for the required source_analysis route (unused on binaries)."""

    name = "source_analysis"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        return AgentResult(agent_name=self.name)


async def run_runtime_discovery(
    spec: AgentTargetSpec,
    *,
    workdir: Path,
    seed: int = 7,
    verifier: VulnerabilityVerifier | None = None,
    policy: Any | None = None,
    max_agent_steps: int = 15,
) -> dict[str, Any]:
    """Execute a blind discovery run through the formal AgentRuntime."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    agent_ws = workdir / "agent_workspace"
    agent_ws.mkdir(parents=True, exist_ok=True)

    metadata: dict[str, Any] = {
        "opaque_case_id": spec.opaque_case_id,
        "target_path": str(spec.target_path),
        "target_sha256": spec.target_sha256,
        "seed_dir": str(spec.seed_dir),
        "time_budget_seconds": spec.time_budget_seconds,
        "max_executions": spec.max_executions,
        "per_input_timeout_seconds": spec.per_input_timeout_seconds,
        "exec_args": list(spec.exec_args),
        "symbolize_frames": spec.symbolize_frames,
        "fuzz_authorized": True,
        "dynamic_validation": True,
        "agent_workspace": str(agent_ws),
    }
    task = Task(
        task_id=spec.opaque_case_id,
        target=Target(
            target_id=spec.opaque_case_id,
            path=str(spec.target_path),
            target_type=TargetType.BINARY,
            language="c",
            file_format="exe",
            metadata=metadata,
        ),
    )
    context = AnalysisContext(task=task)

    registry = AgentRegistry()
    registry.register_many(
        {
            "planner": PlannerAgent(),
            "source_analysis": NoopSourceAgent(),
            "binary_analysis": BlindBinaryObserverAgent(),
            "fuzz": BlindDiscoveryAgent(
                seed=seed,
                workdir=agent_ws,
                policy=policy,
            ),
            "verification": VerificationAgent(
                verifier or MockVerifier()
            ),
            "reviewer": ReviewerAgent(),
            "report": ReportAgent(MockReportGenerator()),
        }
    )

    events: list[dict[str, Any]] = []

    def publish(event: Any) -> None:
        events.append(
            {
                "type": getattr(event, "event_type", type(event).__name__).value
                if isinstance(getattr(event, "event_type", None), str)
                else str(getattr(event, "event_type", type(event).__name__)),
                "task_id": getattr(event, "task_id", None),
                "payload": getattr(event, "payload", None),
                "metadata": getattr(event, "metadata", None),
            }
        )

    runtime = AgentRuntime(
        registry.as_mapping(),
        supervisor=Supervisor(),
        policy=RuntimePolicy(max_agent_steps=max_agent_steps),
        publish_event=publish,
    )
    result = await runtime.run(task, context)
    trace_path = dump_runtime_trace(
        workdir, task.task_id, result, extra_events=events
    )
    return {
        "task_id": task.task_id,
        "trace_path": str(trace_path),
        "route_history": list(result.state["route_history"]),
        "termination_reason": result.termination_reason,
        "step_limit_reached": result.step_limit_reached,
        "execution_failed": result.execution_failed,
        "findings": result.context.findings,
        "evidence": result.context.evidence,
        "messages": result.context.messages,
    }


def dump_runtime_trace(
    workdir: Path,
    task_id: str,
    result,
    *,
    extra_events: list[dict[str, Any]] | None = None,
) -> Path:
    """Persist the AgentMessage / DomainEvent / route history as JSONL."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    final = result.context
    trace = {
        "task_id": task_id,
        "termination_reason": result.termination_reason,
        "step_limit_reached": result.step_limit_reached,
        "execution_failed": result.execution_failed,
        "route_history": list(result.state["route_history"]),
        "messages": [m.model_dump(mode="json") for m in final.messages],
        "events": extra_events or [],
        "findings": [f.model_dump(mode="json") for f in final.findings],
        "evidence": [e.model_dump(mode="json") for e in final.evidence],
    }
    trace_path = workdir / "agent_trace.jsonl"
    trace_path.write_text(
        json.dumps(trace, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return trace_path
