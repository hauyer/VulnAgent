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