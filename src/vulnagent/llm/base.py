"""LLM interface."""

from abc import ABC, abstractmethod
from typing import Any


class BaseLLM(ABC):
    """Provider-independent language model interface."""

    @abstractmethod
    async def generate(self, prompt: str, **kwargs: Any) -> str: ...

