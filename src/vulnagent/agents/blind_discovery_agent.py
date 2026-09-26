"""S1: blind-discovery agents running inside the formal AgentRuntime.

Two real agents with traceable roles:

* ``BlindBinaryObserverAgent`` (route ``binary_analysis``) performs static
  *observation only*: target hash, size and a printable-strings sample.  It
  deliberately emits no findings -- a crash-free binary proves nothing, so
  nothing is invented from static facts.
* ``BlindDiscoveryAgent`` (route ``fuzz``) runs the target-agnostic blind
  discovery loop (:class:`BlindDiscoveryRunner`) against the de-identified
  target and turns root-cause clusters into candidates whose fields come
  only from observations.

Both agents consume only the de-identified ``AgentTargetSpec`` facts carried
in the Task metadata; neither has any view of ground truth, CVE ids or patch
knowledge.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from vulnagent.agents.base import BaseAgent
from vulnagent.benchmark.discovery_ports import (
    AgentTargetSpec,
    BoundedTargetExecutor,
    DiscoveryPolicy,
    SandboxBoundedExecutor,
)
from vulnagent.benchmark.runner import (
    BlindDiscoveryRunner,
    GenericJavaScriptPolicy,
)
from vulnagent.contracts import (
    AgentMessage,
    AgentMessageType,
    AgentResult,
    AnalysisContext,
    Evidence,
    EvidenceType,
    Task,
)
from vulnagent.utils.ids import new_message_id

_STRINGS_RE = re.compile(rb"[ -~]{6,}")


class BlindBinaryObserverAgent(BaseAgent):
    """Static observation of the target binary; no findings by design."""

    name = "binary_analysis"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        path = Path(task.target.path)
        facts: dict[str, object] = {}
        error: str | None = None
        if not path.is_file():
            error = f"target binary missing: {path}"
        else:
            data = path.read_bytes()
            facts["target_sha256"] = hashlib.sha256(data).hexdigest()
            facts["size_bytes"] = len(data)
            facts["strings_sample"] = [
                m.decode("ascii", "replace")
                for m in _STRINGS_RE.findall(data[: 64 * 1024])[:20]
            ]

        evidence = Evidence(
            evidence_id=f"obs-{hashlib.sha256(str(path).encode()).hexdigest()[:12]}",
            task_id=task.task_id,
            evidence_type=EvidenceType.TOOL_RESULT,
            source="blind_binary_observer",
            description=(
                "Static binary observation (hash, size, strings sample); "
                "no vulnerability conclusion drawn from static facts."
            ),
            artifact_path=str(path),
            data={"facts": facts, "error": error},
            reliability=0.95 if not error else 0.0,
            created_by=self.name,
        )
        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="supervisor",
            message_type=AgentMessageType.ANALYSIS_RESULT,
            payload={
                "observations": facts,
                "error": error,
                "conclusion": "static_observation_only",
            },
            evidence_ids=[evidence.evidence_id],
        )
        return AgentResult(
            agent_name=self.name,
            success=error is None,
            messages=[message],
            evidence=[evidence],
            error=error,
        )


class BlindDiscoveryAgent(BaseAgent):
    """Run the bounded blind discovery loop and emit per-cluster candidates."""

    name = "blind_discovery"

    def __init__(
        self,
        *,
        executor: BoundedTargetExecutor | None = None,
        policy: DiscoveryPolicy | None = None,
        seed: int = 7,
        workdir: Path | None = None,
    ) -> None:
        self.executor = executor or SandboxBoundedExecutor()
        self.policy = policy or GenericJavaScriptPolicy()
        self.seed = seed
        self.workdir = workdir or Path("agent_workspace")

    def _spec_from_task(self, task: Task) -> AgentTargetSpec:
        meta = task.target.metadata
        seed_dir = Path(str(meta.get("seed_dir", self.workdir / "seeds")))
        return AgentTargetSpec(
            opaque_case_id=str(meta.get("opaque_case_id", task.task_id)),
            target_path=Path(str(meta.get("target_path", task.target.path))),
            target_sha256=meta.get("target_sha256"),
            seed_dir=seed_dir,
            time_budget_seconds=int(meta.get("time_budget_seconds", 240)),
            max_executions=int(meta.get("max_executions", 240)),
            per_input_timeout_seconds=float(
                meta.get("per_input_timeout_seconds", 30.0)
            ),
            exec_args=tuple(meta.get("exec_args") or ()),
            symbolize_frames=bool(meta.get("symbolize_frames", False)),
        )

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        spec = self._spec_from_task(task)
        if not spec.target_path.is_file():
            return AgentResult(
                agent_name=self.name,
                success=False,
                error=f"target binary missing: {spec.target_path}",
            )
        runner = BlindDiscoveryRunner(self.workdir)
        seed_inputs = [
            p.read_bytes() for p in sorted(spec.seed_dir.glob("*")) if p.is_file()
        ]
        outcome = runner.run(
            spec=spec,
            executor=self.executor,
            policy=self.policy,
            seed=self.seed,
            extra_seed_inputs=seed_inputs,
        )
        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="verification",
            message_type=AgentMessageType.FUZZ_RESULT,
            payload={
                "run_id": outcome.run_id,
                "status": outcome.status,
                "reason": outcome.reason,
                "executions": outcome.executions,
                "crashes": outcome.crashes,
                "clusters": [c.key for c in outcome.clusters],
                "trace_path": (
                    str(outcome.trace_path) if outcome.trace_path else None
                ),
            },
            evidence_ids=[e.evidence_id for e in outcome.evidence],
        )
        return AgentResult(
            agent_name=self.name,
            messages=[message],
            findings=outcome.candidates,
            evidence=outcome.evidence,
        )
