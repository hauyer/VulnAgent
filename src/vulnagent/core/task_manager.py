"""Task lifecycle persistence."""

from typing import Any

from vulnagent.contracts import Target, Task, TaskStatus
from vulnagent.contracts.common import utc_now
from vulnagent.storage.memory import InMemoryStorage
from vulnagent.utils.ids import new_task_id


class InMemoryTaskManager:
    """Manage tasks in process memory for local V0.2 execution."""

    def __init__(
        self,
        storage: InMemoryStorage[Task] | None = None,
    ) -> None:
        self._storage = storage or InMemoryStorage()

    def create_task(
        self,
        target: Target,
        metadata: dict[str, Any] | None = None,
    ) -> Task:
        """Create and persist a new task."""

        task = Task(
            task_id=new_task_id(),
            target=target,
            metadata=metadata or {},
        )

        # 存储层保存自己的副本。
        self._storage.save(
            task.task_id,
            task.model_copy(deep=True),
        )

        # 调用者也拿副本。
        return task.model_copy(deep=True)

    def get_task(
        self,
        task_id: str,
    ) -> Task | None:
        """Get an isolated copy of one task."""

        task = self._storage.get(task_id)

        if task is None:
            return None

        return task.model_copy(deep=True)

    def list_tasks(self) -> list[Task]:
        """Return isolated copies of all tasks."""

        return [
            task.model_copy(deep=True)
            for task in self._storage.list_all()
        ]

    def update_task(
        self,
        task_id: str,
        *,
        status: TaskStatus | None = None,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Task:
        """Update one task and persist the new snapshot."""

        task = self.get_task(task_id)

        if task is None:
            raise KeyError(
                f"Unknown task: {task_id}"
            )

        updated = task.model_copy(deep=True)

        if status is not None:
            updated.status = status

        if error is not None:
            updated.error = error

        # 正常生命周期继续运行时清除旧 error。
        elif (
            status is not None
            and status is not TaskStatus.FAILED
        ):
            updated.error = None

        if metadata is not None:
            updated.metadata.update(metadata)

        updated.updated_at = utc_now()

        self._storage.save(
            task_id,
            updated.model_copy(deep=True),
        )

        return updated.model_copy(deep=True)