"""Process-local domain event bus."""

import logging
from collections import defaultdict
from collections.abc import Callable

from vulnagent.contracts import DomainEvent, EventType
from vulnagent.core.trace_safety import ensure_public_trace_payload


logger = logging.getLogger(__name__)


EventCallback = Callable[[DomainEvent], None]


class EventBus:
    """Publish process-local events without infrastructure dependencies."""

    def __init__(self) -> None:
        self._subscribers: dict[
            EventType,
            list[EventCallback],
        ] = defaultdict(list)

        self._history: dict[
            str,
            list[DomainEvent],
        ] = defaultdict(list)

    def subscribe(
        self,
        event_type: EventType,
        callback: EventCallback,
    ) -> None:
        """Subscribe one callback to one event type."""

        subscribers = self._subscribers[event_type]

        # 防止同一个 callback 被重复注册。
        if callback not in subscribers:
            subscribers.append(callback)

    def publish(self, event: DomainEvent) -> None:
        """Publish an event and isolate subscriber failures."""

        ensure_public_trace_payload(event.payload)

        # 先记录事件。
        # 即使某个 subscriber 出错，事件历史仍然存在。
        self._history[event.task_id].append(
            event.model_copy(deep=True)
        )

        callbacks = list(
            self._subscribers[event.event_type]
        )

        for callback in callbacks:
            try:
                callback(
                    event.model_copy(deep=True)
                )

            except Exception:
                # Event subscriber 属于旁路组件。
                # 不允许它破坏任务主生命周期。
                logger.exception(
                    "Event subscriber failed",
                    extra={
                        "task_id": event.task_id,
                        "event": event.event_type.value,
                        "producer": event.producer,
                    },
                )

    def list_by_task(
        self,
        task_id: str,
    ) -> list[DomainEvent]:
        """Return an isolated copy of a task event timeline."""

        return list(
            event.model_copy(deep=True)
            for event in self._history.get(task_id, [])
        )
