"""Top-level coordinator for the safe mock pipeline."""

import logging

from vulnagent.agents import BinaryAnalysisAgent, FuzzAgent, PlannerAgent, ReportAgent, ReviewerAgent, SourceAuditAgent, VerificationAgent
from vulnagent.core.models import AnalysisContext, TargetType, Task, TaskStatus
from vulnagent.core.pipeline import Pipeline, PipelineStage
from vulnagent.core.state_manager import StateManager
from vulnagent.core.task_manager import InMemoryTaskManager
from vulnagent.evidence.store import InMemoryEvidenceStore

logger = logging.getLogger(__name__)


class Orchestrator:
    """Coordinate agents, state changes, and result persistence."""

    def __init__(self, task_manager: InMemoryTaskManager, evidence_store: InMemoryEvidenceStore) -> None:
        self.task_manager = task_manager
        self.evidence_store = evidence_store
        self.pipeline = Pipeline()
        self.state_manager = StateManager()
        self._contexts: dict[str, AnalysisContext] = {}

    async def run(self, task_id: str) -> AnalysisContext:
        task = self.task_manager.get_task(task_id)
        if task is None:
            raise KeyError(f"Unknown task: {task_id}")
        context = AnalysisContext(task=task)
        analyzer = BinaryAnalysisAgent() if task.target.target_type is TargetType.BINARY else SourceAuditAgent()
        stages = [
            PipelineStage(TaskStatus.PLANNING, PlannerAgent()),
            PipelineStage(TaskStatus.ANALYZING, analyzer),
            PipelineStage(TaskStatus.DYNAMIC_TESTING, FuzzAgent()),
            PipelineStage(TaskStatus.VERIFYING, VerificationAgent()),
            PipelineStage(TaskStatus.VERIFYING, ReviewerAgent()),
            PipelineStage(TaskStatus.REPORTING, ReportAgent()),
        ]
        try:
            self._advance(context, TaskStatus.PROFILING)
            for stage in stages:
                if stage.status is not context.task.status:
                    self._advance(context, stage.status)
                result = await self.pipeline.execute_stage(stage, context)
                if not result.success:
                    raise RuntimeError(result.error or f"Agent failed: {result.agent_name}")
                self.pipeline.merge(context, result, replace_findings=result.agent_name == "verification")
                for evidence in result.evidence:
                    self.evidence_store.add(evidence)
            self._advance(context, TaskStatus.COMPLETED)
        except Exception as exc:
            logger.exception("Pipeline failed for task %s", task_id)
            context.task = self.task_manager.update_task(task_id, status=TaskStatus.FAILED, error=str(exc))
            raise
        self._contexts[task_id] = context
        return context

    def get_context(self, task_id: str) -> AnalysisContext | None:
        return self._contexts.get(task_id)

    def _advance(self, context: AnalysisContext, status: TaskStatus) -> None:
        self.state_manager.validate(context.task.status, status)
        context.task = self.task_manager.update_task(context.task.task_id, status=status)
