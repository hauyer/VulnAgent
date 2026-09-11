"""Provider-neutral LLM interface and public metering values."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class LLMUsage:
    """Provider-reported token counts plus an optional cost estimate."""

    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    cached_prompt_tokens: int | None = None
    cost: float | None = None
    currency: str | None = None
    cost_is_estimate: bool = False

    @property
    def available(self) -> bool:
        """Return whether the provider supplied any standard token count."""

        return any(
            value is not None
            for value in (
                self.prompt_tokens,
                self.completion_tokens,
                self.total_tokens,
            )
        )


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """Assistant text paired with non-sensitive operational metadata."""

    text: str
    usage: LLMUsage = LLMUsage()


@dataclass(frozen=True, slots=True)
class LLMPricing:
    """Versioned per-million-token rates used only for cost estimates."""

    input_per_million: float
    output_per_million: float
    currency: str
    cached_input_per_million: float | None = None
    source_url: str | None = None
    effective_date: str | None = None
    rate_label: str | None = None

    def __post_init__(self) -> None:
        rates = (
            self.input_per_million,
            self.output_per_million,
            self.cached_input_per_million,
        )
        if any(rate is not None and rate < 0 for rate in rates):
            raise ValueError("LLM pricing rates must be non-negative")
        if not self.currency.strip():
            raise ValueError("LLM pricing currency is required")

    def estimate(self, usage: LLMUsage) -> float | None:
        """Estimate one call cost; return unavailable for incomplete usage."""

        if usage.prompt_tokens is None or usage.completion_tokens is None:
            return None
        cached = min(
            usage.cached_prompt_tokens or 0,
            usage.prompt_tokens,
        )
        uncached = usage.prompt_tokens - cached
        cached_rate = (
            self.cached_input_per_million
            if self.cached_input_per_million is not None
            else self.input_per_million
        )
        return (
            uncached * self.input_per_million
            + cached * cached_rate
            + usage.completion_tokens * self.output_per_million
        ) / 1_000_000


class BaseLLM(ABC):
    """Provider-independent language model interface."""

    @abstractmethod
    async def generate(self, prompt: str, **kwargs: Any) -> str: ...

    async def generate_with_usage(self, prompt: str, **kwargs: Any) -> LLMResponse:
        """Generate text with a backward-compatible unavailable-usage value."""

        return LLMResponse(text=await self.generate(prompt, **kwargs))
