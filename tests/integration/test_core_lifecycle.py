import asyncio

import pytest

from vulnagent.agent_runtime import AgentRoute
from vulnagent.bootstrap import build_mock_services
from vulnagent.contracts import (
    EventType,
    Target,
    TargetType,
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


def make_target() -> Target:
    return Target(
        target_id="target",
        path="fixture",
        target_type=TargetType.SOURCE,
    )


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