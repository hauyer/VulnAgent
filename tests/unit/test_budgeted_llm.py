"""L5: BudgetedLLM metering tests (llm/budget)."""

from __future__ import annotations

import pytest

from vulnagent.llm.base import BaseLLM, LLMPricing, LLMResponse, LLMUsage
from vulnagent.llm.budget import BudgetExhaustedError, BudgetedLLM, RunBudget


class FakeLLM(BaseLLM):
    """Deterministic fake adapter returning scripted usage."""

    def __init__(self, usage: LLMUsage | None = None) -> None:
        self.usage = usage
        self.calls = 0

    async def generate(self, prompt: str, **kwargs: object) -> str:
        return "ok"

    async def generate_with_usage(self, prompt: str, **kwargs: object) -> LLMResponse:
        self.calls += 1
        return LLMResponse(
            text="ok",
            usage=self.usage or LLMUsage(),
        )


def _usage(prompt: int, completion: int, cost: float | None = None) -> LLMUsage:
    return LLMUsage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=prompt + completion,
        cost=cost,
    )


class TestBudgetedLLM:
    async def test_metered_usage_accumulates(self) -> None:
        inner = FakeLLM(usage=_usage(prompt=10, completion=5))
        wrapper = BudgetedLLM(
            inner,
            RunBudget(run_id="r1", agent_name="planner", max_calls=2),
        )
        await wrapper.generate("hello")
        assert wrapper.ledger.calls == 1
        assert wrapper.ledger.total_tokens == 15

    async def test_max_calls_raises_budget_exhausted(self) -> None:
        inner = FakeLLM(usage=_usage(prompt=1, completion=1))
        wrapper = BudgetedLLM(
            inner,
            RunBudget(run_id="r1", agent_name="planner", max_calls=1),
        )
        await wrapper.generate("a")
        with pytest.raises(BudgetExhaustedError) as exc:
            await wrapper.generate("b")
        assert exc.value.code == "BUDGET_EXHAUSTED"
        assert exc.value.run_id == "r1"

    async def test_unknown_usage_is_not_zero(self) -> None:
        inner = FakeLLM(usage=None)  # provider gives no usage
        wrapper = BudgetedLLM(
            inner,
            RunBudget(run_id="r1", agent_name="planner"),
        )
        await wrapper.generate("x")
        assert wrapper.ledger.calls == 1
        assert wrapper.ledger.unknown_usage_calls == 1
        assert wrapper.ledger.snapshot()["usage_state"] == "partially_unknown"

    async def test_cost_cap_enforced_with_pricing(self) -> None:
        inner = FakeLLM(usage=_usage(prompt=100, completion=50, cost=0.01))
        pricing = LLMPricing(
            input_per_million=0.5,
            output_per_million=1.5,
            currency="USD",
        )
        wrapper = BudgetedLLM(
            inner,
            RunBudget(run_id="r1", agent_name="planner", max_cost=0.005, currency="USD"),
            pricing=pricing,
        )
        # pre-check: projected cost of the prompt already exceeds the cap
        with pytest.raises(BudgetExhaustedError):
            await wrapper.generate("word " * 300)

    async def test_currency_mismatch_rejected(self) -> None:
        with pytest.raises(ValueError):
            BudgetedLLM(
                FakeLLM(),
                RunBudget(run_id="r1", agent_name="p", max_cost=1.0, currency="USD"),
                pricing=LLMPricing(
                    input_per_million=1.0,
                    output_per_million=1.0,
                    currency="CNY",
                ),
            )

    async def test_never_swaps_in_mock(self) -> None:
        inner = FakeLLM(usage=_usage(prompt=1, completion=1))
        wrapper = BudgetedLLM(inner, RunBudget(run_id="r1", agent_name="p", max_calls=1))
        await wrapper.generate("a")
        with pytest.raises(BudgetExhaustedError):
            await wrapper.generate("b")
        assert inner.calls == 1  # the real adapter call count is untouched
