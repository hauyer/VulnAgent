"""Binary analyzer contract."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BaseBinaryAnalyzer(ABC):
    @abstractmethod
    async def analyze(self, target: Path) -> dict[str, Any]: ...

