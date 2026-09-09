"""Task state transition validation."""

from vulnagent.contracts import TaskStatus


_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.CREATED: {
        TaskStatus.PROFILING,
        TaskStatus.FAILED,
    },

    TaskStatus.PROFILING: {
        TaskStatus.PLANNING,
        TaskStatus.REPORTING,
        TaskStatus.FAILED,
    },

    TaskStatus.PLANNING: {
        TaskStatus.ANALYZING,
        TaskStatus.REPORTING,
        TaskStatus.FAILED,
    },

    TaskStatus.ANALYZING: {
        TaskStatus.DYNAMIC_TESTING,
        TaskStatus.VERIFYING,
        TaskStatus.REPORTING,
        TaskStatus.FAILED,
    },

    TaskStatus.DYNAMIC_TESTING: {
        TaskStatus.VERIFYING,
        TaskStatus.REPORTING,
        TaskStatus.FAILED,
    },

    TaskStatus.VERIFYING: {
        TaskStatus.ANALYZING,
        TaskStatus.DYNAMIC_TESTING,
        TaskStatus.REPORTING,
        TaskStatus.FAILED,
    },

    TaskStatus.REPORTING: {
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
    },

    TaskStatus.COMPLETED: set(),
    TaskStatus.FAILED: set(),
}


_TERMINAL_STATES = frozenset(
    {
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
    }
)


class StateManager:
    """Validate and inspect the VulnAgent task lifecycle."""

    def can_transition(
        self,
        current: TaskStatus,
        target: TaskStatus,
    ) -> bool:
        """Return whether a lifecycle transition is allowed."""
        return target in _TRANSITIONS.get(current, set())

    def validate(
        self,
        current: TaskStatus,
        target: TaskStatus,
    ) -> None:
        """Raise when a lifecycle transition is invalid."""
        if not self.can_transition(current, target):
            raise ValueError(
                f"Invalid task transition: "
                f"{current.value} -> {target.value}"
            )

    def is_terminal(self, status: TaskStatus) -> bool:
        """Return whether the task has reached a terminal state."""
        return status in _TERMINAL_STATES
