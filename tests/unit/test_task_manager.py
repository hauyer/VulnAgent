from vulnagent.contracts import (
    Target,
    TargetType,
    TaskStatus,
)
from vulnagent.core.task_manager import (
    InMemoryTaskManager,
)


def make_target() -> Target:
    return Target(
        target_id="target",
        path="sample.c",
        target_type=TargetType.SOURCE,
    )


def test_create_get_list_and_update() -> None:
    manager = InMemoryTaskManager()

    task = manager.create_task(
        make_target()
    )

    assert (
        manager.get_task(task.task_id)
        == task
    )

    updated = manager.update_task(
        task.task_id,
        status=TaskStatus.PROFILING,
    )

    assert (
        updated.status
        is TaskStatus.PROFILING
    )

    assert manager.list_tasks() == [
        updated
    ]


def test_unknown_task_raises_key_error() -> None:
    manager = InMemoryTaskManager()

    try:
        manager.update_task(
            "missing",
            status=TaskStatus.PROFILING,
        )
    except KeyError as exc:
        assert "Unknown task" in str(exc)
    else:
        raise AssertionError(
            "Expected KeyError"
        )


def test_get_task_returns_isolated_copy() -> None:
    manager = InMemoryTaskManager()

    created = manager.create_task(
        make_target()
    )

    fetched = manager.get_task(
        created.task_id
    )

    assert fetched is not None

    # 外部故意篡改副本。
    fetched.status = TaskStatus.COMPLETED
    fetched.metadata["tampered"] = True

    stored = manager.get_task(
        created.task_id
    )

    assert stored is not None

    # Storage 内真实对象不应该变化。
    assert (
        stored.status
        is TaskStatus.CREATED
    )

    assert "tampered" not in stored.metadata


def test_failure_error_is_persisted() -> None:
    manager = InMemoryTaskManager()

    task = manager.create_task(
        make_target()
    )

    failed = manager.update_task(
        task.task_id,
        status=TaskStatus.FAILED,
        error="synthetic failure",
    )

    assert (
        failed.status
        is TaskStatus.FAILED
    )

    assert (
        failed.error
        == "synthetic failure"
    )

    stored = manager.get_task(
        task.task_id
    )

    assert stored is not None
    assert stored.error == "synthetic failure"