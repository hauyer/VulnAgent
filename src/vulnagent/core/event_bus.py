"""Minimal synchronous event bus placeholder."""

from collections import defaultdict
from collections.abc import Callable
from typing import Any


class EventBus:
    """Publish process-local events without infrastructure dependencies."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[Any], None]]] = defaultdict(list)

    def subscribe(self, event: str, callback: Callable[[Any], None]) -> None:
        self._subscribers[event].append(callback)

    def publish(self, event: str, payload: Any) -> None:
        for callback in self._subscribers[event]:
            callback(payload)

