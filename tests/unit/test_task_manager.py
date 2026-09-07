from vulnagent.core.models import Target, TargetType, TaskStatus
from vulnagent.core.task_manager import InMemoryTaskManager


def test_create_get_list_and_update() -> None:
    manager = InMemoryTaskManager()
    task = manager.create_task(Target(target_id="target", path="sample.c", target_type=TargetType.SOURCE))
    assert manager.get_task(task.task_id) == task
    updated = manager.update_task(task.task_id, status=TaskStatus.PROFILING)
    assert updated.status is TaskStatus.PROFILING
    assert manager.list_tasks() == [updated]

