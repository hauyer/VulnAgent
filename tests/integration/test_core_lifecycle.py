import asyncio
from typing import Any

import pytest

from vulnagent.agent_runtime import (
    AgentRoute,
    AgentRuntime,
    RouteDecision,
    RuntimeState,
    Supervisor,
)
from vulnagent.bootstrap import (
    build_agent_registry,
    build_mock_capabilities,
    build_mock_services,
)
from vulnagent.contracts import (
    AnalysisContext,
    EventType,
    Target,
    TargetType,
    Task,
    TaskStatus,
)
from vulnagent.core.orchestrator import (
    Orchestrator,
)
from vulnagent.core.task_manager import (
    InMemoryTaskManager,
)
from vulnagent.evidence.store import (
    InMemoryEvidenceStore,
)
from vulnagent.core.event_bus import EventBus


def make_target() -> Target:
    return Target(
        target_id="target",
        path="fixture",
        target_type=TargetType.SOURCE,
    )


class ExplodingSupervisor(Supervisor):
    """Supervisor that fails before Planner can run."""

    def decide(
        self,
        task: Task,
        context: AnalysisContext,
        state: RuntimeState,
    ) -> RouteDecision:
        raise RuntimeError("synthetic supervisor failure")


class InvalidSupervisor(Supervisor):
    """Supervisor that returns an invalid initial route."""

    def decide(
        self,
        task: Task,
        context: AnalysisContext,
        state: RuntimeState,
    ) -> RouteDecision:
        return RouteDecision(
            route="invalid-route",  # type: ignore[arg-type]
            reason="synthetic invalid route",
        )


def build_orchestrator_with_supervisor(
    supervisor: Supervisor,
) -> tuple[InMemoryTaskManager, Orchestrator]:
    """Build a real Orchestrator and AgentRuntime with one test supervisor."""

    manager = InMemoryTaskManager()
    evidence_store = InMemoryEvidenceStore()
    event_bus = EventBus()
    capabilities = build_mock_capabilities()
    agents = build_agent_registry(capabilities)
    runtime = AgentRuntime(
        agents.as_mapping(),
        supervisor=supervisor,
        publish_event=event_bus.publish,
    )
    return manager, Orchestrator(
        manager,
        evidence_store,
        runtime,
        event_bus,
    )


async def test_orchestrator_handles_initial_supervisor_exception_with_diagnostic_report() -> None:
    manager, orchestrator = build_orchestrator_with_supervisor(
        ExplodingSupervisor()
    )
    task = manager.create_task(make_target())

    context = await orchestrator.run(task.task_id)

    stored = manager.get_task(task.task_id)
    events = orchestrator.event_bus.list_by_task(task.task_id)
    assert stored is not None
    assert stored.status is TaskStatus.FAILED
    assert context.task.status is TaskStatus.FAILED
    assert context.reports
    assert EventType.TASK_FAILED in {event.event_type for event in events}
    assert any(
        event.event_type is EventType.AGENT_ROUTED
        and event.payload.get("route") == AgentRoute.REPORT.value
        for event in events
    )
    assert not orchestrator.is_running(task.task_id)


async def test_orchestrator_handles_invalid_initial_route_with_diagnostic_report() -> None:
    manager, orchestrator = build_orchestrator_with_supervisor(
        InvalidSupervisor()
    )
    task = manager.create_task(make_target())

    context = await orchestrator.run(task.task_id)

    stored = manager.get_task(task.task_id)
    events = orchestrator.event_bus.list_by_task(task.task_id)
    assert stored is not None
    assert stored.status is TaskStatus.FAILED
    assert context.task.status is TaskStatus.FAILED
    assert context.reports
    assert EventType.TASK_FAILED in {event.event_type for event in events}
    assert any(
        event.event_type is EventType.AGENT_ROUTED
        and event.payload.get("route") == AgentRoute.REPORT.value
        for event in events
    )
    assert not orchestrator.is_running(task.task_id)


async def test_successful_task_reaches_completed() -> None:
    (
        manager,
        evidence_store,
        orchestrator,
    ) = build_mock_services()

    task = manager.create_task(
        make_target()
    )

    context = await orchestrator.run(
        task.task_id
    )

    stored = manager.get_task(
        task.task_id
    )

    assert stored is not None

    assert (
        context.task.status
        is TaskStatus.COMPLETED
    )

    assert (
        stored.status
        is TaskStatus.COMPLETED
    )

    assert not orchestrator.is_running(
        task.task_id
    )

    assert evidence_store.list_by_task(
        task.task_id
    )


async def test_completed_task_cannot_run_again() -> None:
    (
        manager,
        _,
        orchestrator,
    ) = build_mock_services()

    task = manager.create_task(
        make_target()
    )

    await orchestrator.run(
        task.task_id
    )

    with pytest.raises(
        RuntimeError,
        match="already terminal",
    ):
        await orchestrator.run(
            task.task_id
        )

    stored = manager.get_task(
        task.task_id
    )

    assert stored is not None

    # 重复执行不能把 COMPLETED 改成 FAILED。
    assert (
        stored.status
        is TaskStatus.COMPLETED
    )


class FailingRuntime:
    """Runtime stub used to verify failure lifecycle."""

    async def run(
        self,
        task,
        context,
        on_route,
    ):
        on_route(
            AgentRoute.PLANNER
        )

        raise RuntimeError(
            "synthetic runtime failure"
        )


async def test_runtime_failure_reaches_failed() -> None:
    manager = InMemoryTaskManager()
    evidence_store = InMemoryEvidenceStore()

    orchestrator = Orchestrator(
        manager,
        evidence_store,
        FailingRuntime(),
    )

    task = manager.create_task(
        make_target()
    )

    with pytest.raises(
        RuntimeError,
        match="synthetic runtime failure",
    ):
        await orchestrator.run(
            task.task_id
        )

    stored = manager.get_task(
        task.task_id
    )

    assert stored is not None

    assert (
        stored.status
        is TaskStatus.FAILED
    )

    assert (
        stored.error
        == "synthetic runtime failure"
    )

    # 失败 Context 也必须可追踪。
    context = orchestrator.get_context(
        task.task_id
    )

    assert context is not None

    assert (
        context.task.status
        is TaskStatus.FAILED
    )

    assert not orchestrator.is_running(
        task.task_id
    )


class FailedStateWriteManager(InMemoryTaskManager):
    """Task manager that cannot persist the terminal FAILED update."""

    def update_task(
        self,
        task_id: str,
        *,
        status: TaskStatus | None = None,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Task:
        if status is TaskStatus.FAILED:
            raise RuntimeError("synthetic failed-state persistence error")
        return super().update_task(
            task_id,
            status=status,
            error=error,
            metadata=metadata,
        )


async def test_failed_state_persistence_does_not_mask_original_error() -> None:
    manager = FailedStateWriteManager()
    orchestrator = Orchestrator(
        manager,
        InMemoryEvidenceStore(),
        FailingRuntime(),
    )
    task = manager.create_task(make_target())

    with pytest.raises(
        RuntimeError,
        match="synthetic runtime failure",
    ):
        await orchestrator.run(task.task_id)

    assert not orchestrator.is_running(task.task_id)


async def test_failure_generates_task_failed_event() -> None:
    manager = InMemoryTaskManager()
    evidence_store = InMemoryEvidenceStore()

    orchestrator = Orchestrator(
        manager,
        evidence_store,
        FailingRuntime(),
    )

    task = manager.create_task(
        make_target()
    )

    with pytest.raises(RuntimeError):
        await orchestrator.run(
            task.task_id
        )

    events = orchestrator.event_bus.list_by_task(
        task.task_id
    )

    event_types = [
        event.event_type
        for event in events
    ]

    assert (
        EventType.TASK_STARTED
        in event_types
    )

    assert (
        EventType.TASK_FAILED
        in event_types
    )


class BlockingRuntime:
    """Runtime stub used to test duplicate execution protection."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def run(
        self,
        task,
        context,
        on_route,
    ):
        on_route(
            AgentRoute.PLANNER
        )

        self.started.set()

        await self.release.wait()

        raise RuntimeError(
            "blocking runtime released"
        )


async def test_same_task_cannot_run_concurrently() -> None:
    manager = InMemoryTaskManager()
    evidence_store = InMemoryEvidenceStore()

    runtime = BlockingRuntime()

    orchestrator = Orchestrator(
        manager,
        evidence_store,
        runtime,
    )

    task = manager.create_task(
        make_target()
    )

    first_run = asyncio.create_task(
        orchestrator.run(
            task.task_id
        )
    )

    await runtime.started.wait()

    assert orchestrator.is_running(
        task.task_id
    )

    # 第二个请求不能启动同一个任务。
    with pytest.raises(
        RuntimeError,
        match="already running",
    ):
        await orchestrator.run(
            task.task_id
        )

    # 释放第一个运行。
    runtime.release.set()

    with pytest.raises(
        RuntimeError,
        match="blocking runtime released",
    ):
        await first_run

    stored = manager.get_task(
        task.task_id
    )

    assert stored is not None

    assert (
        stored.status
        is TaskStatus.FAILED
    )

    assert not orchestrator.is_running(
        task.task_id
    )
