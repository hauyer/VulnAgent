import pytest

from vulnagent.contracts import TaskStatus
from vulnagent.core.state_manager import StateManager


EXPECTED_TRANSITIONS = {
    TaskStatus.CREATED: {
        TaskStatus.PROFILING,
        TaskStatus.FAILED,
    },

    TaskStatus.PROFILING: {
        TaskStatus.PLANNING,
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


def test_complete_transition_matrix() -> None:
    manager = StateManager()

    for current in TaskStatus:
        for target in TaskStatus:
            expected = (
                target
                in EXPECTED_TRANSITIONS[current]
            )

            assert (
                manager.can_transition(
                    current,
                    target,
                )
                is expected
            )


def test_validate_accepts_valid_transition() -> None:
    manager = StateManager()

    manager.validate(
        TaskStatus.CREATED,
        TaskStatus.PROFILING,
    )


def test_validate_rejects_invalid_transition() -> None:
    manager = StateManager()

    with pytest.raises(
        ValueError,
        match="Invalid task transition",
    ):
        manager.validate(
            TaskStatus.CREATED,
            TaskStatus.COMPLETED,
        )


@pytest.mark.parametrize(
    "status",
    [
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
    ],
)
def test_terminal_states_are_terminal(
    status: TaskStatus,
) -> None:
    manager = StateManager()

    assert manager.is_terminal(status)


@pytest.mark.parametrize(
    "status",
    [
        TaskStatus.CREATED,
        TaskStatus.PROFILING,
        TaskStatus.PLANNING,
        TaskStatus.ANALYZING,
        TaskStatus.DYNAMIC_TESTING,
        TaskStatus.VERIFYING,
        TaskStatus.REPORTING,
    ],
)
def test_active_states_are_not_terminal(
    status: TaskStatus,
) -> None:
    manager = StateManager()

    assert not manager.is_terminal(status)