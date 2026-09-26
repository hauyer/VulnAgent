"""S1 integration: blind discovery routed through the formal AgentRuntime.

Proves the benchmark entry runs inside the real V0.2 runtime (Supervisor /
Router / bounded steps / AgentMessage trace), that a de-identified binary
target flows planner -> binary observer -> blind discovery -> verification
-> review -> report, and that candidate fields stay observation-only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

from vulnagent.benchmark.discovery_ports import (
    AgentTargetSpec,
    ExecutionObservation,
)
from vulnagent.benchmark.runner import DiscoveryPolicy
from vulnagent.contracts import VulnerabilityStatus


class StubExecutor:
    """Deterministic executor: the first input crashes, others are clean."""

    def __init__(self) -> None:
        self.calls: list[Path] = []

    def capabilities(self) -> frozenset[str]:
        return frozenset({"cpu_time_limits"})

    def execute(self, spec: AgentTargetSpec, input_path: Path) -> ExecutionObservation:
        self.calls.append(input_path)
        payload = input_path.read_bytes()
        crashed = payload.startswith(b"CRASH")
        return ExecutionObservation(
            input_sha256=hashlib.sha256(payload).hexdigest(),
            target_sha256=spec.target_sha256 or "",
            exit_code=0xC0000005 if crashed else 0,
            timed_out=False,
            crashed=crashed,
            sanitizer_kind=None if crashed else None,
            stack_frames=("quickjs.c:12",) if crashed else (),
            stderr_artifact=None,
            isolation_capabilities=frozenset({"cpu_time_limits"}),
            stderr_head="stub stderr" if crashed else "",
        )


class FixedPolicy:
    """Two inputs; carries no labels."""

    def propose_inputs(self, spec: AgentTargetSpec, *, seed: int) -> list[bytes]:
        return [b"CRASH-INPUT", b"clean-input"]


def _make_spec(tmp: Path) -> AgentTargetSpec:
    target = tmp / "qjs_asan.exe"
    target.write_bytes(b"MZ" + b"\x00" * 100)
    return AgentTargetSpec(
        opaque_case_id="eg-blind-opaque-001",
        target_path=target,
        target_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
        seed_dir=tmp / "seeds",
        time_budget_seconds=60,
        max_executions=8,
        per_input_timeout_seconds=10.0,
    )


def test_runtime_routes_blind_discovery(tmp_path: Path) -> None:
    spec = _make_spec(tmp_path)
    stub = StubExecutor()
    outcome = asyncio.run(_run_with_injected(stub, spec, tmp_path))
    expected = [
        "planner",
        "binary_analysis",
        "fuzz",
        "verification",
        "reviewer",
        "report",
    ]
    assert outcome["route_history"] == expected
    assert not outcome["execution_failed"]
    assert not outcome["step_limit_reached"]

    # One candidate from the single root-cause cluster, evidence-backed.
    findings = outcome["findings"]
    assert len(findings) == 1
    cand = findings[0]
    assert cand.cwe_id is None  # never invented
    assert cand.location.file_path == "quickjs.c"  # from stack frame only
    # Discovery may not set a final status; independent verification decided.
    assert cand.status is VulnerabilityStatus.REJECTED
    assert cand.evidence_ids
    assert cand.metadata["isolation_capabilities"]  # enforced facts recorded

    evidence = outcome["evidence"]
    crash_ev = [e for e in evidence if "input_sha256" in e.data]
    assert crash_ev, "crash evidence must be recorded with input hash"
    assert crash_ev[0].data["crash_code_kind"] == "SEH access violation"

    # Trace file contains the AgentMessage chain.
    trace = json.loads(
        (tmp_path / "ws" / "agent_trace.jsonl").read_text(encoding="utf-8")
    )
    senders = [m["sender"] for m in trace["messages"]]
    assert "planner" in senders
    assert "blind_discovery" in senders
    assert "verification" in senders
    assert len(stub.calls) == 2  # both inputs executed inside the runtime


async def _run_with_injected(
    stub: StubExecutor, spec: AgentTargetSpec, tmp_path: Path
):
    # Re-run the runtime driver with injected executor/policy by rebuilding
    # the registry directly (kept here to avoid polluting the public driver).
    from vulnagent.agent_runtime import AgentRuntime, RuntimePolicy, Supervisor
    from vulnagent.agents import (
        BlindBinaryObserverAgent,
        BlindDiscoveryAgent,
        PlannerAgent,
        ReportAgent,
        ReviewerAgent,
        VerificationAgent,
    )
    from vulnagent.agents.registry import AgentRegistry
    from vulnagent.benchmark.agent_run import NoopSourceAgent
    from vulnagent.contracts import AnalysisContext, Target, TargetType, Task
    from vulnagent.report.generator import MockReportGenerator
    from vulnagent.verification.verifier import MockVerifier

    agent_ws = tmp_path / "ws" / "agent_workspace"
    task = Task(
        task_id=spec.opaque_case_id,
        target=Target(
            target_id=spec.opaque_case_id,
            path=str(spec.target_path),
            target_type=TargetType.BINARY,
            language="c",
            file_format="exe",
            metadata={
                "opaque_case_id": spec.opaque_case_id,
                "target_path": str(spec.target_path),
                "target_sha256": spec.target_sha256,
                "seed_dir": str(spec.seed_dir),
                "time_budget_seconds": spec.time_budget_seconds,
                "max_executions": spec.max_executions,
                "per_input_timeout_seconds": spec.per_input_timeout_seconds,
                "fuzz_authorized": True,
                "dynamic_validation": True,
                "agent_workspace": str(agent_ws),
            },
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
                executor=stub,
                policy=FixedPolicy(),
                seed=1,
                workdir=agent_ws,
            ),
            "verification": VerificationAgent(MockVerifier()),
            "reviewer": ReviewerAgent(),
            "report": ReportAgent(MockReportGenerator()),
        }
    )
    runtime = AgentRuntime(
        registry.as_mapping(),
        supervisor=Supervisor(),
        policy=RuntimePolicy(max_agent_steps=15),
    )
    result = await runtime.run(task, context)
    from vulnagent.benchmark.agent_run import dump_runtime_trace

    dump_runtime_trace(tmp_path / "ws", task.task_id, result)
    return {
        "task_id": task.task_id,
        "route_history": list(result.state["route_history"]),
        "termination_reason": result.termination_reason,
        "step_limit_reached": result.step_limit_reached,
        "execution_failed": result.execution_failed,
        "findings": result.context.findings,
        "evidence": result.context.evidence,
        "messages": result.context.messages,
    }
