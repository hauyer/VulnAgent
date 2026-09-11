"""LLM provider registry."""

from datetime import datetime, timezone

from vulnagent.llm.base import BaseLLM, LLMPricing
from vulnagent.llm.mock import MockLLM
from vulnagent.llm.openai_compatible import DeepSeekAdapter, GLMAdapter, KimiAdapter
from vulnagent.settings import Settings


class LLMRouter:
    """Resolve configured providers without exposing vendors to business code."""

    def __init__(self) -> None:
        self._providers: dict[str, BaseLLM] = {"mock": MockLLM()}
        self._required_settings = {
            "deepseek": "DEEPSEEK_API_KEY",
            "glm": "GLM_API_KEY",
            "kimi": "KIMI_API_KEY",
        }

    @classmethod
    def from_settings(cls, settings: Settings) -> "LLMRouter":
        """Register configured providers while keeping missing keys explicit."""
        router = cls()
        if settings.deepseek_api_key:
            router.register(
                "deepseek",
                DeepSeekAdapter(
                    api_key=settings.deepseek_api_key,
                    base_url=settings.deepseek_base_url,
                    model=settings.deepseek_model,
                    timeout_seconds=settings.llm_timeout_seconds,
                    pricing=_deepseek_pricing(settings),
                ),
            )
        if settings.glm_api_key:
            router.register(
                "glm",
                GLMAdapter(
                    api_key=settings.glm_api_key,
                    base_url=settings.glm_base_url,
                    model=settings.glm_model,
                    timeout_seconds=settings.llm_timeout_seconds,
                    pricing=_pricing(
                        input_rate=settings.glm_input_cost_per_million,
                        cached_rate=settings.glm_cached_input_cost_per_million,
                        output_rate=settings.glm_output_cost_per_million,
                        currency=settings.glm_cost_currency,
                        source_url="https://docs.bigmodel.cn/cn/guide/start/pricing",
                        rate_label="standard_pay_as_you_go",
                    ),
                ),
            )
        if settings.kimi_api_key:
            router.register(
                "kimi",
                KimiAdapter(
                    api_key=settings.kimi_api_key,
                    base_url=settings.kimi_base_url,
                    model=settings.kimi_model,
                    timeout_seconds=settings.llm_timeout_seconds,
                    pricing=_pricing(
                        input_rate=settings.kimi_input_cost_per_million,
                        cached_rate=settings.kimi_cached_input_cost_per_million,
                        output_rate=settings.kimi_output_cost_per_million,
                        currency=settings.kimi_cost_currency,
                        source_url="https://platform.kimi.com/docs/pricing/chat-k26",
                        rate_label="standard_pay_as_you_go",
                    ),
                ),
            )
        return router

    def register(self, name: str, provider: BaseLLM) -> None:
        self._providers[name] = provider

    def get(self, name: str) -> BaseLLM:
        normalized = name.strip().casefold()
        try:
            return self._providers[normalized]
        except KeyError as exc:
            required = self._required_settings.get(normalized)
            if required is not None:
                raise ValueError(
                    f"LLM provider {normalized!r} is not configured; set {required}"
                ) from exc
            raise KeyError(f"Unknown LLM provider: {name}") from exc


def _pricing(
    *,
    input_rate: float | None,
    cached_rate: float | None,
    output_rate: float | None,
    currency: str,
    source_url: str,
    rate_label: str | None = None,
) -> LLMPricing | None:
    """Build pricing only when both billable standard rates are configured."""

    if input_rate is None or output_rate is None:
        return None
    return LLMPricing(
        input_per_million=input_rate,
        cached_input_per_million=cached_rate,
        output_per_million=output_rate,
        currency=currency,
        source_url=source_url,
        effective_date="2026-09-11",
        rate_label=rate_label,
    )


def _deepseek_pricing(
    settings: Settings, *, now: datetime | None = None
) -> LLMPricing | None:
    """Resolve Flash pricing, including DeepSeek's UTC peak schedule."""

    explicit = (
        settings.deepseek_input_cost_per_million,
        settings.deepseek_cached_input_cost_per_million,
        settings.deepseek_output_cost_per_million,
    )
    if any(value is not None for value in explicit):
        if explicit[0] is None or explicit[2] is None:
            raise ValueError(
                "custom DeepSeek pricing requires input and output rates"
            )
        return _pricing(
            input_rate=explicit[0],
            cached_rate=explicit[1],
            output_rate=explicit[2],
            currency=settings.deepseek_cost_currency,
            source_url="https://api-docs.deepseek.com/quick_start/pricing",
            rate_label="custom",
        )
    if settings.deepseek_model.casefold() not in {
        "deepseek-flash",
        "deepseek-v4-flash",
        "deepseek-v4-flash-vision-exp",
    }:
        return None
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    peak = current.weekday() < 5 and (
        1 <= current.hour < 4 or 6 <= current.hour < 10
    )
    return LLMPricing(
        input_per_million=0.30 if peak else 0.15,
        cached_input_per_million=0.006 if peak else 0.003,
        output_per_million=1.20 if peak else 0.60,
        currency="USD",
        source_url="https://api-docs.deepseek.com/quick_start/pricing",
        effective_date="2026-09-11",
        rate_label="weekday_peak" if peak else "off_peak",
    )
