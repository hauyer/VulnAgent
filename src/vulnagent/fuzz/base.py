"""Fuzzer contract."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BaseFuzzer(ABC):
    @abstractmethod
    async def run(self, target: Path) -> dict[str, Any]: ...

