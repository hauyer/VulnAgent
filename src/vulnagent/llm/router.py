"""LLM provider registry."""

from vulnagent.llm.base import BaseLLM
from vulnagent.llm.mock import MockLLM


class LLMRouter:
    """Resolve configured providers without exposing vendors to business code."""

    def __init__(self) -> None:
        self._providers: dict[str, BaseLLM] = {"mock": MockLLM()}

    def register(self, name: str, provider: BaseLLM) -> None:
        self._providers[name] = provider

    def get(self, name: str) -> BaseLLM:
        try:
            return self._providers[name]
        except KeyError as exc:
            raise KeyError(f"Unknown LLM provider: {name}") from exc

