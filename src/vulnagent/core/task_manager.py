"""Task lifecycle persistence."""

from typing import Any

from vulnagent.contracts import Target, Task, TaskStatus
from vulnagent.contracts.common import utc_now
from vulnagent.storage.memory import InMemoryStorage
from vulnagent.utils.ids import new_task_id


class InMemoryTaskManager:
    """Manage tasks in process memory for V0.1."""

    def __init__(self, storage: InMemoryStorage[Task] | None = None) -> None:
        self._storage = storage or InMemoryStorage()

    def create_task(self, target: Target, metadata: dict[str, Any] | None = None) -> Task:
        task = Task(task_id=new_task_id(), target=target, metadata=metadata or {})
        return self._storage.save(task.task_id, task)

    def get_task(self, task_id: str) -> Task | None:
        return self._storage.get(task_id)

    def list_tasks(self) -> list[Task]:
        return self._storage.list_all()

    def update_task(self, task_id: str, *, status: TaskStatus | None = None, error: str | None = None, metadata: dict[str, Any] | None = None) -> Task:
        task = self.get_task(task_id)
        if task is None:
            raise KeyError(f"Unknown task: {task_id}")
        updated = task.model_copy(deep=True)
        if status is not None:
            updated.status = status
        updated.error = error
        if metadata:
            updated.metadata.update(metadata)
        updated.updated_at = utc_now()
        return self._storage.save(task_id, updated)
