"""Task state transition validation."""

from vulnagent.contracts import TaskStatus

_TRANSITIONS = {
    TaskStatus.CREATED: {TaskStatus.PROFILING, TaskStatus.FAILED},
    TaskStatus.PROFILING: {TaskStatus.PLANNING, TaskStatus.FAILED},
    TaskStatus.PLANNING: {TaskStatus.ANALYZING, TaskStatus.REPORTING, TaskStatus.FAILED},
    TaskStatus.ANALYZING: {TaskStatus.DYNAMIC_TESTING, TaskStatus.VERIFYING, TaskStatus.REPORTING, TaskStatus.FAILED},
    TaskStatus.DYNAMIC_TESTING: {TaskStatus.VERIFYING, TaskStatus.REPORTING, TaskStatus.FAILED},
    TaskStatus.VERIFYING: {TaskStatus.ANALYZING, TaskStatus.DYNAMIC_TESTING, TaskStatus.REPORTING, TaskStatus.FAILED},
    TaskStatus.REPORTING: {TaskStatus.COMPLETED, TaskStatus.FAILED},
    TaskStatus.COMPLETED: set(),
    TaskStatus.FAILED: set(),
}


class StateManager:
    """Validate the dynamic V0.2 task lifecycle envelope."""

    def validate(self, current: TaskStatus, target: TaskStatus) -> None:
        if target not in _TRANSITIONS[current]:
            raise ValueError(f"Invalid task transition: {current.value} -> {target.value}")
