"""Deterministic mock LLM."""

import json

from typing import Any

from vulnagent.llm.base import BaseLLM


class MockLLM(BaseLLM):
    async def generate(self, prompt: str, **kwargs: Any) -> str:
        if kwargs.get("response_format") == {"type": "json_object"}:
            return json.dumps(
                {
                    "rationale_summary": (
                        "Use the bounded deterministic plan; prioritize "
                        "evidence-producing analysis before verification."
                    ),
                    "risk_focus": [],
                }
            )
        return f"[mock] received {len(prompt)} characters"
