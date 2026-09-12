"""Small provider adapters for OpenAI-compatible chat-completion APIs."""

from __future__ import annotations

import asyncio
import logging
from time import monotonic
from typing import Any
from urllib.parse import urlparse

import httpx

from vulnagent.llm.base import BaseLLM, LLMPricing, LLMResponse, LLMUsage


LOGGER = logging.getLogger(__name__)


class LLMProviderError(RuntimeError):
    """Public, credential-safe failure raised by a model adapter."""


class OpenAICompatibleLLM(BaseLLM):
    """Call one configured provider without leaking vendor details to Agents."""

    provider = "openai-compatible"
    max_tokens_field = "max_tokens"
    fixed_temperature: float | None = None
    # Some providers fix ``temperature`` server-side and reject explicit values.
    omit_temperature: bool = False
    # Some providers replace the ``thinking`` switch with their own reasoning
    # controls and reject the cross-provider ``thinking`` field entirely.
    omit_thinking: bool = False
    rate_limit_retry_delays: tuple[float, ...] = ()
    min_request_interval_seconds = 0.0

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        timeout_seconds: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        pricing: LLMPricing | None = None,
    ) -> None:
        if not api_key.strip():
            raise ValueError(f"{self.provider} API key is required")
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("LLM base URL must be an absolute HTTP(S) URL")
        if not model.strip():
            raise ValueError("LLM model name is required")
        if timeout_seconds <= 0:
            raise ValueError("LLM timeout must be positive")
        self._api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self._transport = transport
        self.pricing = pricing
        self._request_slot_lock = asyncio.Lock()
        self._last_request_started = 0.0

    async def _wait_for_request_slot(self) -> None:
        """Serialize and pace calls for providers with low entry-tier RPM."""

        async with self._request_slot_lock:
            remaining = (
                self.min_request_interval_seconds
                - (monotonic() - self._last_request_started)
            )
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._last_request_started = monotonic()

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        """Return non-streaming assistant text from a bounded chat request."""
        return (await self.generate_with_usage(prompt, **kwargs)).text

    async def generate_with_usage(
        self, prompt: str, **kwargs: Any
    ) -> LLMResponse:
        """Return assistant text and provider-reported token usage."""
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")
        allowed = {
            "system_prompt",
            "max_tokens",
            "temperature",
            "response_format",
            "thinking",
        }
        unexpected = sorted(set(kwargs).difference(allowed))
        if unexpected:
            raise ValueError(f"unsupported LLM options: {', '.join(unexpected)}")
        messages: list[dict[str, str]] = []
        system_prompt = kwargs.get("system_prompt")
        if system_prompt:
            messages.append({"role": "system", "content": str(system_prompt)})
        messages.append({"role": "user", "content": prompt})
        requested_temperature = float(kwargs.get("temperature", 0.0))
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if not self.omit_temperature:
            payload["temperature"] = (
                self.fixed_temperature
                if self.fixed_temperature is not None
                else requested_temperature
            )
        payload[self.max_tokens_field] = int(kwargs.get("max_tokens", 512))
        if kwargs.get("response_format") is not None:
            payload["response_format"] = kwargs["response_format"]
        thinking = kwargs.get("thinking")
        if thinking is not None and not self.omit_thinking:
            if (
                not isinstance(thinking, dict)
                or thinking.get("type") not in {"enabled", "disabled"}
                or set(thinking) != {"type"}
            ):
                raise ValueError(
                    "thinking must be {'type': 'enabled'} or {'type': 'disabled'}"
                )
            payload["thinking"] = {"type": thinking["type"]}

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self._transport,
            ) as client:
                for attempt in range(len(self.rate_limit_retry_delays) + 1):
                    await self._wait_for_request_slot()
                    response = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers={
                            "Authorization": f"Bearer {self._api_key}",
                            "Content-Type": "application/json",
                        },
                        json=payload,
                    )
                    if (
                        response.status_code == 429
                        and attempt < len(self.rate_limit_retry_delays)
                    ):
                        delay = _rate_limit_delay(
                            response.headers.get("Retry-After"),
                            fallback=self.rate_limit_retry_delays[attempt],
                        )
                        LOGGER.warning(
                            "%s rate limited; retrying after %.1f seconds "
                            "(attempt %d/%d)",
                            self.provider,
                            delay,
                            attempt + 1,
                            len(self.rate_limit_retry_delays),
                        )
                        await asyncio.sleep(delay)
                        continue
                    response.raise_for_status()
                    data = response.json()
                    break
        except httpx.HTTPStatusError as exc:
            raise LLMProviderError(
                f"{self.provider} request failed with HTTP "
                f"{exc.response.status_code}"
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise LLMProviderError(
                f"{self.provider} request failed: {type(exc).__name__}"
            ) from exc

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMProviderError(
                f"{self.provider} returned an invalid chat-completion response"
            ) from exc
        if not isinstance(content, str) or not content.strip():
            raise LLMProviderError(f"{self.provider} returned empty content")
        usage = _parse_usage(data.get("usage"))
        if self.pricing is not None:
            estimate = self.pricing.estimate(usage)
            if estimate is not None:
                usage = LLMUsage(
                    prompt_tokens=usage.prompt_tokens,
                    completion_tokens=usage.completion_tokens,
                    total_tokens=usage.total_tokens,
                    cached_prompt_tokens=usage.cached_prompt_tokens,
                    cost=estimate,
                    currency=self.pricing.currency.upper(),
                    cost_is_estimate=True,
                )
        return LLMResponse(text=content, usage=usage)


def _non_negative_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _rate_limit_delay(value: str | None, *, fallback: float) -> float:
    """Return a bounded Retry-After delay without parsing provider bodies."""

    try:
        parsed = float(value) if value is not None else fallback
    except ValueError:
        parsed = fallback
    return min(max(parsed, fallback, 1.0), 120.0)


def _parse_usage(value: Any) -> LLMUsage:
    """Normalize common OpenAI-compatible usage shapes without private CoT."""

    if not isinstance(value, dict):
        return LLMUsage()
    prompt = _non_negative_int(value.get("prompt_tokens", value.get("input_tokens")))
    completion = _non_negative_int(
        value.get("completion_tokens", value.get("output_tokens"))
    )
    total = _non_negative_int(value.get("total_tokens"))
    cached_candidates = [
        value.get("cached_tokens"),
        value.get("prompt_cache_hit_tokens"),
    ]
    details = value.get("prompt_tokens_details")
    if isinstance(details, dict):
        cached_candidates.append(details.get("cached_tokens"))
    cached = next(
        (
            parsed
            for item in cached_candidates
            if (parsed := _non_negative_int(item)) is not None
        ),
        None,
    )
    if total is None and prompt is not None and completion is not None:
        total = prompt + completion
    return LLMUsage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=total,
        cached_prompt_tokens=cached,
    )


class DeepSeekAdapter(OpenAICompatibleLLM):
    """DeepSeek chat-completion adapter."""

    provider = "deepseek"


class GLMAdapter(OpenAICompatibleLLM):
    """Zhipu GLM chat-completion adapter."""

    provider = "glm"


class KimiAdapter(OpenAICompatibleLLM):
    """Moonshot Kimi K3 chat-completion adapter.

    Kimi K3 (platform.kimi.com, ``api.moonshot.cn/v1``) fixes ``temperature``
    at 1.0 and ``top_p`` at 0.95, and replaces the older ``thinking`` switch
    with the ``reasoning_effort`` control while keeping preserved thinking
    always on.  This adapter therefore omits both fields instead of sending
    the cross-provider benchmark's temperature=0 / thinking-disabled values,
    which K3 would otherwise reject.
    """

    provider = "kimi"
    max_tokens_field = "max_completion_tokens"
    omit_temperature = True
    omit_thinking = True
    # Entry-tier Moonshot accounts may expose a low requests-per-minute limit.
    # Honor Retry-After when present and otherwise use bounded backoff.
    rate_limit_retry_delays = (20.0, 40.0, 60.0)
    min_request_interval_seconds = 21.0


__all__ = [
    "DeepSeekAdapter",
    "GLMAdapter",
    "KimiAdapter",
    "LLMProviderError",
    "OpenAICompatibleLLM",
    "_rate_limit_delay",
    "_parse_usage",
]
