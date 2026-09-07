"""Minimal synchronous event bus placeholder."""

from collections import defaultdict
from collections.abc import Callable
from vulnagent.contracts import DomainEvent, EventType


class EventBus:
    """Publish process-local events without infrastructure dependencies."""

    def __init__(self) -> None:
        self._subscribers: dict[EventType, list[Callable[[DomainEvent], None]]] = defaultdict(list)
        self._history: dict[str, list[DomainEvent]] = defaultdict(list)

    def subscribe(self, event: EventType, callback: Callable[[DomainEvent], None]) -> None:
        self._subscribers[event].append(callback)

    def publish(self, event: DomainEvent) -> None:
        self._history[event.task_id].append(event)
        for callback in self._subscribers[event.event_type]:
            callback(event)

    def list_by_task(self, task_id: str) -> list[DomainEvent]:
        """Return an isolated task event timeline."""
        return list(self._history[task_id])
