import pytest

from vulnagent.contracts import (
    DomainEvent,
    EventType,
)
from vulnagent.core.event_bus import EventBus


def make_event(
    task_id: str = "task-1",
) -> DomainEvent:
    return DomainEvent(
        event_type=EventType.TASK_STARTED,
        task_id=task_id,
        producer="test",
    )


def test_publish_records_history() -> None:
    bus = EventBus()

    event = make_event()

    bus.publish(event)

    history = bus.list_by_task(
        event.task_id
    )

    assert history == [event]


def test_history_is_isolated_copy() -> None:
    bus = EventBus()

    event = make_event()

    bus.publish(event)

    first = bus.list_by_task(
        event.task_id
    )

    first.clear()

    second = bus.list_by_task(
        event.task_id
    )

    assert second == [event]


def test_history_events_and_payloads_are_isolated_copies() -> None:
    bus = EventBus()
    event = DomainEvent(
        event_type=EventType.AGENT_ROUTED,
        task_id="task-1",
        producer="test",
        payload={"route": "planner", "nested": {"attempt": 1}},
    )

    bus.publish(event)
    event.payload["route"] = "tampered"

    first = bus.list_by_task("task-1")
    first[0].payload["nested"]["attempt"] = 99

    stored = bus.list_by_task("task-1")
    assert stored[0].payload == {
        "route": "planner",
        "nested": {"attempt": 1},
    }


def test_subscriber_receives_event() -> None:
    bus = EventBus()

    received = []

    bus.subscribe(
        EventType.TASK_STARTED,
        received.append,
    )

    event = make_event()

    bus.publish(event)

    assert received == [event]


def test_duplicate_subscription_is_ignored() -> None:
    bus = EventBus()

    received = []

    callback = received.append

    bus.subscribe(
        EventType.TASK_STARTED,
        callback,
    )

    bus.subscribe(
        EventType.TASK_STARTED,
        callback,
    )

    event = make_event()

    bus.publish(event)

    assert received == [event]


def test_broken_subscriber_does_not_break_publish() -> None:
    bus = EventBus()

    received = []

    def broken_callback(
        event: DomainEvent,
    ) -> None:
        raise RuntimeError(
            "subscriber failed"
        )

    bus.subscribe(
        EventType.TASK_STARTED,
        broken_callback,
    )

    bus.subscribe(
        EventType.TASK_STARTED,
        received.append,
    )

    event = make_event()

    # 不应抛出异常
    bus.publish(event)

    # 后面的健康 subscriber 仍然执行
    assert received == [event]

    # history 仍然存在
    assert bus.list_by_task(
        event.task_id
    ) == [event]


def test_subscriber_mutation_is_isolated_from_history_and_peers() -> None:
    bus = EventBus()
    received: list[DomainEvent] = []

    def mutating_callback(event: DomainEvent) -> None:
        event.payload["route"] = "tampered"

    bus.subscribe(EventType.AGENT_ROUTED, mutating_callback)
    bus.subscribe(EventType.AGENT_ROUTED, received.append)

    event = DomainEvent(
        event_type=EventType.AGENT_ROUTED,
        task_id="task-1",
        producer="test",
        payload={"route": "planner"},
    )
    bus.publish(event)

    assert received[0].payload == {"route": "planner"}
    assert bus.list_by_task("task-1")[0].payload == {
        "route": "planner"
    }


def test_task_histories_are_isolated() -> None:
    bus = EventBus()
    first = make_event("task-1")
    second = make_event("task-2")

    bus.publish(first)
    bus.publish(second)

    assert bus.list_by_task("task-1") == [first]
    assert bus.list_by_task("task-2") == [second]
    assert bus.list_by_task("missing") == []


@pytest.mark.parametrize(
    "field_name",
    [
        "chain_of_thought",
        "chain-of-thought",
        "private_reasoning",
        "hidden_reasoning",
        "raw_cot",
        "reasoning_tokens",
    ],
)
def test_private_reasoning_fields_are_rejected_structurally(
    field_name: str,
) -> None:
    bus = EventBus()
    event = DomainEvent(
        event_type=EventType.AGENT_ROUTED,
        task_id="task-1",
        producer="test",
        payload={"nested": [{field_name: object()}]},
    )

    with pytest.raises(ValueError, match="non-public reasoning"):
        bus.publish(event)

    assert bus.list_by_task("task-1") == []
