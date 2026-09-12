"""Bounded, credential-safe LLM provider smoke verification.

Used by the acceptance ``run`` action for group A. It makes at most one real
classification call per configured provider and records only public success
signals and usage counts -- never keys, raw responses, or private reasoning.
This is not the canonical 20-sample comparison (which remains the CLI
``experiments.run_llm_comparison`` job); it proves that configured adapters
can actually reach their vendors.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from vulnagent.llm.router import LLMRouter
from vulnagent.settings import Settings


class ProviderSmokeResult(BaseModel):
    provider: str
    ok: bool
    error_type: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    cost: float | None = None
    currency: str | None = None
    cost_is_estimate: bool = False


class ProviderSmokeReport(BaseModel):
    started_at: str
    providers: list[ProviderSmokeResult] = Field(default_factory=list)


_PROMPT = json.dumps(
    {
        "task": "respond with a fixed JSON object",
        "output_schema": {"ok": "boolean"},
        "constraints": ["return JSON only", "do not reveal chain-of-thought"],
    },
    ensure_ascii=False,
    separators=(",", ":"),
)


async def run_provider_smoke(
    settings: Settings,
    *,
    providers: list[str] | None = None,
) -> ProviderSmokeReport:
    """Make one bounded call per real provider and report public signals."""

    router = LLMRouter.from_settings(settings)
    names = [name.strip().casefold() for name in (providers or ["deepseek", "glm", "kimi"])]
    results: list[ProviderSmokeResult] = []
    for name in names:
        try:
            adapter = router.get(name)
        except (KeyError, ValueError) as exc:
            results.append(
                ProviderSmokeResult(provider=name, ok=False, error_type=type(exc).__name__)
            )
            continue
        try:
            response = await adapter.generate_with_usage(
                _PROMPT,
                system_prompt="You are a JSON responder. Return only the requested object.",
                max_tokens=64,
                temperature=0.0,
                response_format={"type": "json_object"},
                thinking={"type": "disabled"},
            )
            usage = response.usage
            results.append(
                ProviderSmokeResult(
                    provider=name,
                    ok=True,
                    prompt_tokens=usage.prompt_tokens,
                    completion_tokens=usage.completion_tokens,
                    total_tokens=usage.total_tokens,
                    cost=usage.cost,
                    currency=usage.currency,
                    cost_is_estimate=usage.cost_is_estimate,
                )
            )
        except Exception as exc:  # noqa: BLE001 - adapter failures are normalized here
            results.append(
                ProviderSmokeResult(
                    provider=name,
                    ok=False,
                    error_type=type(exc).__name__,
                )
            )
    return ProviderSmokeReport(started_at=_now_iso(), providers=results)


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
