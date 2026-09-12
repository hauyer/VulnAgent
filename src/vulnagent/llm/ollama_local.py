"""Credential-free Ollama adapter for the loopback-only course laboratory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx


DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class OllamaLocalError(RuntimeError):
    """A sanitized local Ollama connectivity or response error."""


def validate_ollama_base_url(value: str) -> str:
    """Return a normalized URL, rejecting every non-loopback destination."""

    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in _LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Ollama URL must use credential-free HTTP on 127.0.0.1, localhost, or ::1"
        )
    return normalized


@dataclass(frozen=True, slots=True)
class OllamaGeneration:
    """Provider-neutral response returned to the scanner business layer."""

    text: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class OllamaLocalClient:
    """Small async adapter around Ollama's local tags and chat endpoints."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_OLLAMA_BASE_URL,
        timeout_seconds: float = 90.0,
        response_limit: int = 6000,
        num_gpu: int = 0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = validate_ollama_base_url(base_url)
        self.timeout_seconds = timeout_seconds
        self.response_limit = response_limit
        self.num_gpu = num_gpu
        self._transport = transport

    async def list_models(self) -> list[str]:
        """List actual locally installed model names from ``/api/tags``."""

        payload = await self._request("GET", "/api/tags")
        models = payload.get("models")
        if not isinstance(models, list):
            return []
        names: list[str] = []
        for item in models:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("model")
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
        return sorted(set(names), key=str.casefold)

    async def generate(
        self,
        *,
        model: str,
        system_prompt: str,
        prompt: str,
        max_tokens: int = 192,
        temperature: float = 0.0,
    ) -> OllamaGeneration:
        """Generate one bounded response through Ollama's local chat API.

        The native endpoint lets the course configuration explicitly select
        CPU mode when the host CUDA runtime is unhealthy.  Its message shape
        remains equivalent to the OpenAI-compatible chat boundary exposed to
        the scanner.
        """

        payload = await self._request(
            "POST",
            "/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "think": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                    "num_gpu": self.num_gpu,
                },
            },
        )
        try:
            text = payload["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise OllamaLocalError("Local Ollama returned an invalid chat response") from exc
        if not isinstance(text, str):
            raise OllamaLocalError("Local Ollama returned a non-text chat response")
        return OllamaGeneration(
            text=text[: self.response_limit],
            prompt_tokens=_optional_int(payload.get("prompt_eval_count")),
            completion_tokens=_optional_int(payload.get("eval_count")),
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout_seconds,
                transport=self._transport,
                trust_env=False,
            ) as client:
                response = await client.request(method, path, json=json)
                response.raise_for_status()
                payload = response.json()
        except httpx.TimeoutException as exc:
            raise OllamaLocalError("Local Ollama request timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise OllamaLocalError(
                f"Local Ollama returned HTTP {exc.response.status_code}"
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise OllamaLocalError("Unable to communicate with local Ollama") from exc
        if not isinstance(payload, dict):
            raise OllamaLocalError("Local Ollama returned an invalid JSON document")
        return payload


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


__all__ = [
    "DEFAULT_OLLAMA_BASE_URL",
    "OllamaGeneration",
    "OllamaLocalClient",
    "OllamaLocalError",
    "validate_ollama_base_url",
]
