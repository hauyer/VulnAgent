"""Top-level coordinator for the safe mock pipeline."""

import logging
from dataclasses import dataclass

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AnalysisContext, DomainEvent, EvidenceRepository, EventType, ModuleExecutionError, TargetType, TaskRepository, TaskStatus
from vulnagent.core.pipeline import Pipeline, PipelineStage
from vulnagent.core.state_manager import StateManager
from vulnagent.core.event_bus import EventBus

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AgentSuite:
    """All replaceable agents required by the V0.1 pipeline."""

    planner: BaseAgent
    source_analysis: BaseAgent
    binary_analysis: BaseAgent
    fuzz: BaseAgent
    verification: BaseAgent
    reviewer: BaseAgent
    report: BaseAgent


class Orchestrator:
    """Coordinate agents, state changes, and result persistence."""

    def __init__(self, task_manager: TaskRepository, evidence_store: EvidenceRepository, agents: AgentSuite, event_bus: EventBus | None = None) -> None:
        self.task_manager = task_manager
        self.evidence_store = evidence_store
        self.pipeline = Pipeline()
        self.state_manager = StateManager()
        self.event_bus = event_bus or EventBus()
        self.agents = agents
        self._contexts: dict[str, AnalysisContext] = {}

    async def run(self, task_id: str) -> AnalysisContext:
        task = self.task_manager.get_task(task_id)
        if task is None:
            raise KeyError(f"Unknown task: {task_id}")
        context = AnalysisContext(task=task)
        self._publish(EventType.TASK_STARTED, task_id, "orchestrator")
        analyzer = self.agents.binary_analysis if task.target.target_type is TargetType.BINARY else self.agents.source_analysis
        stages = [
            PipelineStage(TaskStatus.PLANNING, self.agents.planner),
            PipelineStage(TaskStatus.ANALYZING, analyzer),
            PipelineStage(TaskStatus.DYNAMIC_TESTING, self.agents.fuzz),
            PipelineStage(TaskStatus.VERIFYING, self.agents.verification),
            PipelineStage(TaskStatus.VERIFYING, self.agents.reviewer),
            PipelineStage(TaskStatus.REPORTING, self.agents.report),
        ]
        try:
            self._advance(context, TaskStatus.PROFILING)
            for stage in stages:
                if stage.status is not context.task.status:
                    self._advance(context, stage.status)
                self._publish(EventType.AGENT_STARTED, task_id, stage.agent.name)
                result = await self.pipeline.execute_stage(stage, context)
                if not result.success:
                    raise ModuleExecutionError(result.error or f"Agent failed: {result.agent_name}")
                self.pipeline.merge(context, result, replace_findings=result.agent_name == "verification")
                for evidence in result.evidence:
                    self.evidence_store.save(evidence)
                    self._publish(EventType.EVIDENCE_ADDED, task_id, result.agent_name, {"evidence_id": evidence.evidence_id})
                self._publish(EventType.AGENT_FINISHED, task_id, result.agent_name)
            self._advance(context, TaskStatus.COMPLETED)
        except Exception as exc:
            logger.exception("Pipeline failed for task %s", task_id)
            context.task = self.task_manager.update_task(task_id, status=TaskStatus.FAILED, error=str(exc))
            self._publish(EventType.TASK_FAILED, task_id, "orchestrator", {"error": str(exc)})
            raise
        self._contexts[task_id] = context
        return context

    def get_context(self, task_id: str) -> AnalysisContext | None:
        return self._contexts.get(task_id)

    def _advance(self, context: AnalysisContext, status: TaskStatus) -> None:
        self.state_manager.validate(context.task.status, status)
        context.task = self.task_manager.update_task(context.task.task_id, status=status)

    def _publish(self, event_type: EventType, task_id: str, producer: str, payload: dict[str, object] | None = None) -> None:
        logger.info("orchestration event", extra={"task_id": task_id, "agent": producer, "module": "core.orchestrator", "event": event_type.value})
        self.event_bus.publish(DomainEvent(event_type=event_type, task_id=task_id, producer=producer, payload=payload or {}))
