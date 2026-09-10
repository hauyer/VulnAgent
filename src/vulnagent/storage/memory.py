"""In-memory storage backend."""

from typing import Generic, TypeVar

from vulnagent.storage.base import BaseStorage

T = TypeVar("T")


class InMemoryStorage(BaseStorage[T], Generic[T]):
    """Process-local storage intended for tests and V0.1 only."""

    def __init__(self) -> None:
        self._items: dict[str, T] = {}

    def save(self, key: str, value: T) -> T:
        self._items[key] = value
        return value

    def get(self, key: str) -> T | None:
        return self._items.get(key)

    def list_all(self) -> list[T]:
        return list(self._items.values())

