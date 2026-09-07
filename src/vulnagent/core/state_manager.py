"""Task state transition validation."""

from vulnagent.core.models import TaskStatus

_TRANSITIONS = {
    TaskStatus.CREATED: {TaskStatus.PROFILING, TaskStatus.FAILED},
    TaskStatus.PROFILING: {TaskStatus.PLANNING, TaskStatus.FAILED},
    TaskStatus.PLANNING: {TaskStatus.ANALYZING, TaskStatus.FAILED},
    TaskStatus.ANALYZING: {TaskStatus.DYNAMIC_TESTING, TaskStatus.FAILED},
    TaskStatus.DYNAMIC_TESTING: {TaskStatus.VERIFYING, TaskStatus.FAILED},
    TaskStatus.VERIFYING: {TaskStatus.REPORTING, TaskStatus.FAILED},
    TaskStatus.REPORTING: {TaskStatus.COMPLETED, TaskStatus.FAILED},
    TaskStatus.COMPLETED: set(),
    TaskStatus.FAILED: set(),
}


class StateManager:
    """Validate the explicit V0.1 task lifecycle."""

    def validate(self, current: TaskStatus, target: TaskStatus) -> None:
        if target not in _TRANSITIONS[current]:
            raise ValueError(f"Invalid task transition: {current.value} -> {target.value}")

