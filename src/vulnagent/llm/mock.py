"""Deterministic mock LLM."""

from typing import Any

from vulnagent.llm.base import BaseLLM


class MockLLM(BaseLLM):
    async def generate(self, prompt: str, **kwargs: Any) -> str:
        return f"[mock] received {len(prompt)} characters"

