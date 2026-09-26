"""Per-run LLM budget metering (L5).

Wraps ``BaseLLM.generate_with_usage`` with a run/agent-scoped ledger: checks
limits before a request, accumulates real usage after it, counts calls that
come back without provider usage as ``unknown`` (never as zero cost), and
raises a structured ``BudgetExhaustedError`` the Supervisor may degrade into
*no-model analysis / UNCERTAIN*.  It never silently swaps in ``MockLLM``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from vulnagent.llm.base import BaseLLM, LLMPricing, LLMResponse, LLMUsage


class BudgetExhaustedError(RuntimeError):
    """Raised when a run/agent exceeds its declared LLM budget.

    ``code`` matches the S6 API error vocabulary so callers can map it to a
    structured ``BUDGET_EXHAUSTED`` envelope.
    """

    code = "BUDGET_EXHAUSTED"

    def __init__(self, run_id: str, agent_name: str, reason: str) -> None:
        self.run_id = run_id
        self.agent_name = agent_name
        self.reason = reason
        super().__init__(f"[{run_id}/{agent_name}] {reason}")


@dataclass(frozen=True, slots=True)
class RunBudget:
    """Declared limits for one run/agent; ``None`` means unbounded for a metric."""

    run_id: str
    agent_name: str
    max_calls: int | None = None
    max_tokens: int | None = None
    max_cost: float | None = None
    currency: str | None = None


@dataclass(slots=True)
class BudgetLedger:
    """Accumulated usage for one run/agent."""

    run_id: str
    agent_name: str
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost: float = 0.0
    unknown_usage_calls: int = 0  # provider gave no token counts

    def snapshot(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "agent_name": self.agent_name,
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cost": self.cost,
            "cost_currency": None,
            "unknown_usage_calls": self.unknown_usage_calls,
            "usage_state": (
                "metered" if self.unknown_usage_calls == 0 else "partially_unknown"
            ),
        }


class BudgetedLLM:
    """Metering wrapper around any :class:`BaseLLM`.

    The wrapped adapter stays the single real model call site; this wrapper
    only adds the ledger, the pre/post checks and structured exhaustion.
    """

    def __init__(
        self,
        llm: BaseLLM,
        budget: RunBudget,
        pricing: LLMPricing | None = None,
    ) -> None:
        if pricing is not None and budget.currency and pricing.currency != budget.currency:
            raise ValueError(
                f"budget currency {budget.currency} != pricing currency {pricing.currency}"
            )
        self.llm = llm
        self.budget = budget
        self.pricing = pricing
        self.ledger = BudgetLedger(budget.run_id, budget.agent_name)

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        return (await self.generate_with_usage(prompt, **kwargs)).text

    async def generate_with_usage(self, prompt: str, **kwargs: Any) -> LLMResponse:
        self._check_before(prompt)
        response = await self.llm.generate_with_usage(prompt, **kwargs)
        self._accumulate(response.usage)
        self._check_after()
        return response

    def _check_before(self, prompt: str) -> None:
        budget = self.budget
        if budget.max_calls is not None and self.ledger.calls >= budget.max_calls:
            raise BudgetExhaustedError(
                budget.run_id, budget.agent_name, f"max_calls={budget.max_calls} reached"
            )
        prompt_tokens = _estimate_tokens(prompt)
        if budget.max_tokens is not None and self.ledger.total_tokens + prompt_tokens > budget.max_tokens:
            raise BudgetExhaustedError(
                budget.run_id,
                budget.agent_name,
                f"projected tokens exceed max_tokens={budget.max_tokens}",
            )
        if budget.max_cost is not None and self.pricing is not None:
            projected = self.ledger.cost + _estimate_cost(prompt, self.pricing)
            if projected > budget.max_cost:
                raise BudgetExhaustedError(
                    budget.run_id,
                    budget.agent_name,
                    f"projected cost exceeds max_cost={budget.max_cost} {budget.currency or ''}".strip(),
                )

    def _accumulate(self, usage: LLMUsage) -> None:
        self.ledger.calls += 1
        if not usage.available:
            # Unknown usage must be recorded as unknown, never as zero cost.
            self.ledger.unknown_usage_calls += 1
            return
        self.ledger.prompt_tokens += usage.prompt_tokens or 0
        self.ledger.completion_tokens += usage.completion_tokens or 0
        self.ledger.total_tokens += usage.total_tokens or (
            (usage.prompt_tokens or 0) + (usage.completion_tokens or 0)
        )
        if usage.cost is not None:
            self.ledger.cost += usage.cost
        elif self.pricing is not None:
            estimated = self.pricing.estimate(usage)
            if estimated is not None:
                self.ledger.cost += estimated

    def _check_after(self) -> None:
        budget = self.budget
        if budget.max_tokens is not None and self.ledger.total_tokens > budget.max_tokens:
            raise BudgetExhaustedError(
                budget.run_id, budget.agent_name, f"tokens exceeded max_tokens={budget.max_tokens}"
            )
        if budget.max_cost is not None and self.ledger.cost > budget.max_cost:
            raise BudgetExhaustedError(
                budget.run_id,
                budget.agent_name,
                f"cost exceeded max_cost={budget.max_cost} {budget.currency or ''}".strip(),
            )


def _estimate_tokens(text: str) -> int:
    """Conservative token estimate (chars / 3, min 1)."""
    return max(1, len(text) // 3)


def _estimate_cost(text: str, pricing: LLMPricing) -> float:
    usage = LLMUsage(prompt_tokens=_estimate_tokens(text), completion_tokens=0)
    estimated = pricing.estimate(usage)
    return estimated if estimated is not None else 0.0
