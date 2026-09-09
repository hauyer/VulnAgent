"""System-level task lifecycle owner for the V0.2 agent runtime."""

import logging

from vulnagent.agent_runtime import AgentRoute, AgentRuntime
from vulnagent.contracts import (
    AnalysisContext,
    DomainEvent,
    EvidenceRepository,
    EventType,
    ModuleExecutionError,
    Task,
    TaskRepository,
    TaskStatus,
)
from vulnagent.core.event_bus import EventBus
from vulnagent.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class Orchestrator:
    """Own task lifecycle while delegating agent flow to the runtime."""

    def __init__(
        self,
        task_manager: TaskRepository,
        evidence_store: EvidenceRepository,
        runtime: AgentRuntime,
        event_bus: EventBus | None = None,
    ) -> None:
        self.task_manager = task_manager
        self.evidence_store = evidence_store

        self.state_manager = StateManager()
        self.event_bus = event_bus or EventBus()
        self.runtime = runtime

        # 保存最近一次任务上下文。
        # 成功和失败任务都应该可追踪。
        self._contexts: dict[
            str,
            AnalysisContext,
        ] = {}

        # 防止同一个 task_id 同时进入两次运行流程。
        self._running_task_ids: set[str] = set()

    async def run(
        self,
        task_id: str,
    ) -> AnalysisContext:
        """Run one task exactly once through the lifecycle."""

        # --------------------------------------
        # 1. 并发保护
        # --------------------------------------

        if task_id in self._running_task_ids:
            raise RuntimeError(
                f"Task is already running: {task_id}"
            )

        task = self.task_manager.get_task(task_id)

        if task is None:
            raise KeyError(
                f"Unknown task: {task_id}"
            )

        # --------------------------------------
        # 2. 启动状态校验
        # --------------------------------------

        self._ensure_runnable(task)

        # 从这里开始拥有这个 task 的运行权。
        # 在第一次 await 之前加入集合，
        # 防止 asyncio 并发请求重复启动。
        self._running_task_ids.add(task_id)

        context = AnalysisContext(
            task=task,
        )

        # 不要等成功以后再缓存。
        # 失败情况下也必须能看到最后 Context。
        self._contexts[task_id] = context

        try:
            # ----------------------------------
            # 3. CREATED -> PROFILING
            # ----------------------------------

            self._advance(
                context,
                TaskStatus.PROFILING,
            )

            self._publish(
                EventType.TASK_STARTED,
                task_id,
                "orchestrator",
                {
                    "status": context.task.status.value,
                },
            )

            # ----------------------------------
            # 4. Agent Runtime
            # ----------------------------------

            outcome = await self.runtime.run(
                context.task,
                context,
                on_route=lambda route: self._on_route(
                    context,
                    route,
                ),
            )

            # Runtime 正常返回，
            # 但没有报告，仍然属于失败。
            if not context.reports:
                raise ModuleExecutionError(
                    "Agent runtime ended without a report: "
                    f"{outcome.termination_reason}"
                )

            # ----------------------------------
            # 5. Evidence persistence
            # ----------------------------------

            for evidence in context.evidence:
                self.evidence_store.save(evidence)

                self._publish(
                    EventType.EVIDENCE_ADDED,
                    task_id,
                    evidence.created_by,
                    {
                        "evidence_id": evidence.evidence_id,
                    },
                )

            # ----------------------------------
            # 6. REPORTING -> COMPLETED
            # ----------------------------------

            self._advance(
                context,
                TaskStatus.COMPLETED,
            )

            return context

        except Exception as exc:
            logger.exception(
                "Pipeline failed for task %s",
                task_id,
            )

            # 尽最大努力把生命周期收敛到 FAILED。
            self._mark_failed(
                context,
                exc,
            )

            self._publish(
                EventType.TASK_FAILED,
                task_id,
                "orchestrator",
                {
                    "error": "task execution failed",
                    "error_type": type(exc).__name__,
                    "status": context.task.status.value,
                },
            )

            raise

        finally:
            # 无论成功失败，都必须释放运行标记。
            self._running_task_ids.discard(
                task_id
            )

    def get_context(
        self,
        task_id: str,
    ) -> AnalysisContext | None:
        """Return the latest known context for a task."""

        return self._contexts.get(task_id)

    def is_running(
        self,
        task_id: str,
    ) -> bool:
        """Return whether the task currently owns an execution slot."""

        return task_id in self._running_task_ids

    def _ensure_runnable(
        self,
        task: Task,
    ) -> None:
        """Ensure a task can enter a fresh orchestration run."""

        if self.state_manager.is_terminal(
            task.status
        ):
            raise RuntimeError(
                f"Task is already terminal: "
                f"{task.task_id} ({task.status.value})"
            )

        # 当前 V0.2 不实现 checkpoint resume。
        # 所以不能假装从半途中恢复。
        if task.status is not TaskStatus.CREATED:
            raise RuntimeError(
                f"Task cannot start from status "
                f"{task.status.value}: "
                f"{task.task_id}"
            )

    def _advance(
        self,
        context: AnalysisContext,
        status: TaskStatus,
        *,
        error: str | None = None,
    ) -> None:
        """Validate and persist one lifecycle transition."""

        self.state_manager.validate(
            context.task.status,
            status,
        )

        context.task = self.task_manager.update_task(
            context.task.task_id,
            status=status,
            error=error,
        )

    def _mark_failed(
        self,
        context: AnalysisContext,
        exc: Exception,
    ) -> None:
        """Best-effort transition of an active task to FAILED."""

        current = context.task.status

        if current is TaskStatus.FAILED:
            return

        if self.state_manager.is_terminal(
            current
        ):
            return

        if not self.state_manager.can_transition(
            current,
            TaskStatus.FAILED,
        ):
            logger.error(
                "Task cannot transition to FAILED",
                extra={
                    "task_id": context.task.task_id,
                    "status": current.value,
                },
            )
            return

        try:
            self._advance(
                context,
                TaskStatus.FAILED,
                error=str(exc),
            )

        except Exception:
            # 不允许失败状态持久化异常覆盖最初的业务异常。
            logger.exception(
                "Unable to persist FAILED state for task %s",
                context.task.task_id,
            )

    def _on_route(
        self,
        context: AnalysisContext,
        route: AgentRoute,
    ) -> None:
        """Translate a runtime route into the public task lifecycle."""

        status = {
            AgentRoute.PLANNER:
                TaskStatus.PLANNING,

            AgentRoute.SOURCE_ANALYSIS:
                TaskStatus.ANALYZING,

            AgentRoute.BINARY_ANALYSIS:
                TaskStatus.ANALYZING,

            AgentRoute.FUZZ:
                TaskStatus.DYNAMIC_TESTING,

            AgentRoute.VERIFICATION:
                TaskStatus.VERIFYING,

            AgentRoute.REVIEWER:
                TaskStatus.VERIFYING,

            AgentRoute.REPORT:
                TaskStatus.REPORTING,
        }[route]

        # 相同生命周期阶段无需重复持久化。
        if status != context.task.status:
            self._advance(
                context,
                status,
            )

    def _publish(
        self,
        event_type: EventType,
        task_id: str,
        producer: str,
        payload: dict[str, object] | None = None,
    ) -> None:
        """Publish one structured lifecycle event."""

        logger.info(
            "orchestration event",
            extra={
                "task_id": task_id,
                "agent": producer,
                "module": "core.orchestrator",
                "event": event_type.value,
            },
        )

        self.event_bus.publish(
            DomainEvent(
                event_type=event_type,
                task_id=task_id,
                producer=producer,
                payload=payload or {},
            )
        )
