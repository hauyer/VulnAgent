"""Loopback-only HTTP adapter with bounded response handling."""

from __future__ import annotations

import ipaddress
import time
from urllib.parse import urlsplit

import httpx

from .models import EndpointSpec, ProbeObservation, RobustnessCase


def validate_loopback_endpoint(endpoint: EndpointSpec) -> None:
    parsed = urlsplit(endpoint.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("dynamic endpoint must be an HTTP(S) loopback URL")
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("dynamic endpoint must not contain credentials, queries, or fragments")
    hostname = parsed.hostname.casefold()
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise ValueError("remote dynamic targets are forbidden; use localhost or a loopback IP") from exc
        if not address.is_loopback:
            raise ValueError("remote dynamic targets are forbidden")
    if endpoint.method.upper() not in {"POST", "PUT", "PATCH"}:
        raise ValueError("only bounded body-bearing API methods are supported")
    if not 0.1 <= endpoint.timeout_seconds <= 15.0:
        raise ValueError("endpoint timeout is outside the defensive bound")


class HttpxLocalServiceProbe:
    """Send one local request without redirects, proxies, or body retention."""

    async def execute(
        self,
        endpoint: EndpointSpec,
        case: RobustnessCase,
    ) -> ProbeObservation:
        validate_loopback_endpoint(endpoint)
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(
                trust_env=False,
                follow_redirects=False,
                timeout=endpoint.timeout_seconds,
            ) as client:
                async with client.stream(
                    endpoint.method.upper(), endpoint.url, json=case.request_body
                ) as response:
                    response_bytes = 0
                    async for chunk in response.aiter_bytes():
                        response_bytes += len(chunk)
                        if response_bytes >= endpoint.max_response_bytes:
                            break
                    return ProbeObservation(
                        status_code=response.status_code,
                        duration_ms=int((time.monotonic() - started) * 1000),
                        response_bytes=min(response_bytes, endpoint.max_response_bytes),
                    )
        except httpx.TimeoutException:
            return ProbeObservation(
                status_code=None,
                duration_ms=int((time.monotonic() - started) * 1000),
                timed_out=True,
                transport_error="timeout",
            )
        except httpx.HTTPError as exc:
            return ProbeObservation(
                status_code=None,
                duration_ms=int((time.monotonic() - started) * 1000),
                transport_error=type(exc).__name__,
            )
