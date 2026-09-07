"""System-level task lifecycle owner for the V0.2 agent runtime."""

import logging
from vulnagent.agent_runtime import AgentRoute, AgentRuntime
from vulnagent.contracts import AnalysisContext, DomainEvent, EvidenceRepository, EventType, ModuleExecutionError, TaskRepository, TaskStatus
from vulnagent.core.state_manager import StateManager
from vulnagent.core.event_bus import EventBus

logger = logging.getLogger(__name__)


class Orchestrator:
    """Own tasks and persistence while delegating agent flow to the runtime."""

    def __init__(self, task_manager: TaskRepository, evidence_store: EvidenceRepository, runtime: AgentRuntime, event_bus: EventBus | None = None) -> None:
        self.task_manager = task_manager
        self.evidence_store = evidence_store
        self.state_manager = StateManager()
        self.event_bus = event_bus or EventBus()
        self.runtime = runtime
        self._contexts: dict[str, AnalysisContext] = {}

    async def run(self, task_id: str) -> AnalysisContext:
        task = self.task_manager.get_task(task_id)
        if task is None:
            raise KeyError(f"Unknown task: {task_id}")
        context = AnalysisContext(task=task)
        self._publish(EventType.TASK_STARTED, task_id, "orchestrator")
        try:
            self._advance(context, TaskStatus.PROFILING)
            outcome = await self.runtime.run(task, context, on_route=lambda route: self._on_route(context, route))
            if not context.reports:
                raise ModuleExecutionError(f"Agent runtime ended without a report: {outcome.termination_reason}")
            for evidence in context.evidence:
                self.evidence_store.save(evidence)
                self._publish(EventType.EVIDENCE_ADDED, task_id, evidence.created_by, {"evidence_id": evidence.evidence_id})
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

    def _on_route(self, context: AnalysisContext, route: AgentRoute) -> None:
        status = {
            AgentRoute.PLANNER: TaskStatus.PLANNING,
            AgentRoute.SOURCE_ANALYSIS: TaskStatus.ANALYZING,
            AgentRoute.BINARY_ANALYSIS: TaskStatus.ANALYZING,
            AgentRoute.FUZZ: TaskStatus.DYNAMIC_TESTING,
            AgentRoute.VERIFICATION: TaskStatus.VERIFYING,
            AgentRoute.REVIEWER: TaskStatus.VERIFYING,
            AgentRoute.REPORT: TaskStatus.REPORTING,
        }[route]
        if status is not context.task.status:
            self._advance(context, status)

    def _publish(self, event_type: EventType, task_id: str, producer: str, payload: dict[str, object] | None = None) -> None:
        logger.info("orchestration event", extra={"task_id": task_id, "agent": producer, "module": "core.orchestrator", "event": event_type.value})
        self.event_bus.publish(DomainEvent(event_type=event_type, task_id=task_id, producer=producer, payload=payload or {}))
