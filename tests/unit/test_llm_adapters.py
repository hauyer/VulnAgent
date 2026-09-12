"""Provider adapters and bounded LLM planning advisory behavior."""

import json
from datetime import datetime, timezone

import httpx
import pytest

from vulnagent.agents.planner_agent import PlannerAgent
from vulnagent.contracts import AnalysisContext, Target, TargetType, Task
from vulnagent.llm.base import BaseLLM, LLMPricing
from vulnagent.llm.openai_compatible import (
    DeepSeekAdapter,
    GLMAdapter,
    KimiAdapter,
    LLMProviderError,
    _parse_usage,
)
from vulnagent.llm.router import LLMRouter
from vulnagent.llm.router import _deepseek_pricing
from vulnagent.settings import Settings


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter_type", "base_url", "model", "token_field"),
    [
        (DeepSeekAdapter, "https://api.deepseek.test", "deepseek-v4-flash", "max_tokens"),
        (GLMAdapter, "https://glm.test/api/paas/v4", "glm-5.2", "max_tokens"),
        (KimiAdapter, "https://api.moonshot.test/v1", "kimi-k3", "max_completion_tokens"),
    ],
)
async def test_provider_adapter_uses_bearer_chat_completion_contract(
    adapter_type,
    base_url: str,
    model: str,
    token_field: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert str(request.url) == f"{base_url}/chat/completions"
        assert request.headers["Authorization"] == "Bearer test-secret"
        assert payload["model"] == model
        assert payload["messages"][-1] == {"role": "user", "content": "hello"}
        assert payload["stream"] is False
        assert payload[token_field] == 512
        if adapter_type is KimiAdapter:
            # Kimi K3 fixes temperature/top_p server-side and replaces the
            # thinking switch with reasoning_effort, so both are omitted.
            assert "temperature" not in payload
            assert "thinking" not in payload
        else:
            assert payload["temperature"] == 0.0
            assert payload["thinking"] == {"type": "disabled"}
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "safe answer"}}]},
        )

    adapter = adapter_type(
        api_key="test-secret",
        base_url=base_url,
        model=model,
        transport=httpx.MockTransport(handler),
    )

    assert await adapter.generate(
        "hello", thinking={"type": "disabled"}, temperature=0.0
    ) == "safe answer"


@pytest.mark.asyncio
async def test_provider_error_does_not_leak_key_or_response_body() -> None:
    adapter = DeepSeekAdapter(
        api_key="never-expose-me",
        base_url="https://api.deepseek.test",
        model="deepseek-v4-flash",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(401, text="sensitive vendor body")
        ),
    )

    with pytest.raises(LLMProviderError) as captured:
        await adapter.generate("hello")

    assert "401" in str(captured.value)
    assert "never-expose-me" not in str(captured.value)
    assert "sensitive vendor body" not in str(captured.value)


@pytest.mark.asyncio
async def test_kimi_retries_rate_limit_without_reading_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                429,
                headers={"Retry-After": "2"},
                text="private provider detail",
            )
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "safe answer"}}]},
        )

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("vulnagent.llm.openai_compatible.asyncio.sleep", fake_sleep)
    adapter = KimiAdapter(
        api_key="test-secret",
        base_url="https://api.moonshot.test/v1",
        model="kimi-k3",
        transport=httpx.MockTransport(handler),
    )
    adapter.min_request_interval_seconds = 0.0

    assert await adapter.generate("hello") == "safe answer"
    assert calls == 2
    assert delays == [20.0]


@pytest.mark.asyncio
async def test_provider_usage_is_normalized_and_cost_is_estimated() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "safe answer"}}],
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 50,
                    "total_tokens": 150,
                    "prompt_cache_hit_tokens": 40,
                },
            },
        )

    adapter = DeepSeekAdapter(
        api_key="test-secret",
        base_url="https://api.deepseek.test",
        model="deepseek-flash",
        transport=httpx.MockTransport(handler),
        pricing=LLMPricing(
            input_per_million=10,
            cached_input_per_million=2,
            output_per_million=20,
            currency="USD",
        ),
    )

    response = await adapter.generate_with_usage("hello")

    assert response.text == "safe answer"
    assert response.usage.prompt_tokens == 100
    assert response.usage.completion_tokens == 50
    assert response.usage.total_tokens == 150
    assert response.usage.cached_prompt_tokens == 40
    assert response.usage.cost == pytest.approx(0.00168)
    assert response.usage.currency == "USD"
    assert response.usage.cost_is_estimate is True


def test_kimi_cached_token_usage_shape_is_normalized() -> None:
    usage = _parse_usage(
        {
            "prompt_tokens": 80,
            "completion_tokens": 20,
            "total_tokens": 100,
            "cached_tokens": 32,
        }
    )

    assert usage.prompt_tokens == 80
    assert usage.completion_tokens == 20
    assert usage.total_tokens == 100
    assert usage.cached_prompt_tokens == 32


def test_deepseek_pricing_selects_documented_utc_time_tier() -> None:
    settings = Settings(_env_file=None, deepseek_model="deepseek-v4-flash")
    peak = _deepseek_pricing(
        settings,
        now=datetime(2026, 9, 11, 3, 30, tzinfo=timezone.utc),
    )
    off_peak = _deepseek_pricing(
        settings,
        now=datetime(2026, 9, 11, 5, 30, tzinfo=timezone.utc),
    )

    assert peak is not None and peak.rate_label == "weekday_peak"
    assert peak.input_per_million == 0.30
    assert off_peak is not None and off_peak.rate_label == "off_peak"
    assert off_peak.input_per_million == 0.15


def test_router_supports_three_configured_real_providers() -> None:
    router = LLMRouter.from_settings(
        Settings(
            deepseek_api_key="deepseek-key",
            glm_api_key="glm-key",
            kimi_api_key="kimi-key",
        )
    )

    assert isinstance(router.get("deepseek"), DeepSeekAdapter)
    assert isinstance(router.get("glm"), GLMAdapter)
    assert isinstance(router.get("kimi"), KimiAdapter)
    assert router.get("deepseek").pricing.currency == "USD"
    assert router.get("glm").pricing.currency == "CNY"
    assert router.get("kimi").pricing.currency == "CNY"


def test_selected_provider_without_key_fails_fast() -> None:
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        LLMRouter.from_settings(Settings(_env_file=None)).get("deepseek")

    with pytest.raises(ValueError, match="KIMI_API_KEY"):
        LLMRouter.from_settings(Settings(_env_file=None)).get("kimi")


class AdvisoryLLM(BaseLLM):
    async def generate(self, prompt: str, **kwargs) -> str:
        assert "deterministic supervisor remains route authority" in prompt
        assert kwargs["response_format"] == {"type": "json_object"}
        assert kwargs["thinking"] == {"type": "disabled"}
        return json.dumps(
            {
                "rationale_summary": "Prioritize tainted input to dangerous sinks.",
                "risk_focus": ["CWE-78", "taint-path"],
            }
        )


@pytest.mark.asyncio
async def test_planner_accepts_public_advice_without_delegating_route_authority() -> None:
    task = Task(
        task_id="task",
        target=Target(
            target_id="target",
            path="private/path/is/not/sent",
            target_type=TargetType.SOURCE,
            language="python",
        ),
    )

    result = await PlannerAgent(AdvisoryLLM()).run(
        task,
        AnalysisContext(task=task),
    )
    payload = result.messages[0].payload

    assert payload["rationale_summary"].startswith("Prioritize")
    assert payload["metadata"]["llm_advisory"]["status"] == "accepted"
    assert payload["metadata"]["llm_advisory"]["risk_focus"] == [
        "CWE-78",
        "taint-path",
    ]
    assert payload["metadata"]["routing_authority"] == "deterministic_supervisor"


class FailingLLM(BaseLLM):
    async def generate(self, prompt: str, **kwargs) -> str:
        raise RuntimeError("provider unavailable")


@pytest.mark.asyncio
async def test_planner_falls_back_without_failing_the_pipeline() -> None:
    task = Task(
        task_id="task",
        target=Target(
            target_id="target",
            path="fixture",
            target_type=TargetType.BINARY,
        ),
    )

    result = await PlannerAgent(FailingLLM()).run(
        task,
        AnalysisContext(task=task),
    )

    advisory = result.messages[0].payload["metadata"]["llm_advisory"]
    assert advisory["status"] == "fallback"
    assert advisory["error_type"] == "RuntimeError"
    assert result.messages[0].payload["selected_agents"][0] == "binary_analysis"
