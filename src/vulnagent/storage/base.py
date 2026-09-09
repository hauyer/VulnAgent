"""Generic storage abstraction."""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

T = TypeVar("T")


class BaseStorage(ABC, Generic[T]):
    """Minimal replaceable key-value storage contract."""

    @abstractmethod
    def save(self, key: str, value: T) -> T: ...

    @abstractmethod
    def get(self, key: str) -> T | None: ...

    @abstractmethod
    def list_all(self) -> list[T]: ...

