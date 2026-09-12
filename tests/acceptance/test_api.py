"""Acceptance API endpoints surface honest, credential-free status."""

from __future__ import annotations

from fastapi.testclient import TestClient

from vulnagent.api.app import create_app
from vulnagent.settings import Settings


def _client() -> TestClient:
    return TestClient(create_app(settings=Settings(_env_file=None)))


def test_overview_returns_three_honest_groups() -> None:
    with _client() as client:
        response = client.get("/api/acceptance/overview")
        assert response.status_code == 200
        body = response.json()
        assert body["total_groups"] == 3
        assert body["passed_groups"] == 0
        assert body["status_text"] == "0/3"
        assert {group["group_id"] for group in body["groups"]} == {"a", "b", "c"}
        assert body["notices"]


def test_group_detail_and_unknown_group() -> None:
    with _client() as client:
        assert client.get("/api/acceptance/groups/a").status_code == 200
        assert client.get("/api/acceptance/groups/b").status_code == 200
        assert client.get("/api/acceptance/groups/c").status_code == 200
        assert client.get("/api/acceptance/groups/unknown").status_code == 404


def test_providers_never_leak_credentials() -> None:
    with _client() as client:
        response = client.get("/api/acceptance/providers")
        assert response.status_code == 200
        providers = response.json()
        assert len(providers) == 3
        for provider in providers:
            assert "api_key" not in provider
            assert provider["configured"] is False
        text = str(providers)
        assert "sk-" not in text


def test_run_group_a_without_keys_is_rejected() -> None:
    with _client() as client:
        response = client.post("/api/acceptance/groups/a/run")
        assert response.status_code == 400


def test_run_group_a_unknown_provider_is_rejected() -> None:
    with _client() as client:
        response = client.post(
            "/api/acceptance/groups/a/run",
            json={"providers": ["openai"]},
        )
        assert response.status_code == 400
        assert "Unknown provider" in response.json()["detail"]


def test_run_group_a_unconfigured_provider_is_rejected() -> None:
    with _client() as client:
        response = client.post(
            "/api/acceptance/groups/a/run",
            json={"providers": ["deepseek", "glm"]},
        )
        assert response.status_code == 400
        assert "not configured" in response.json()["detail"]


def test_run_group_b_ignores_provider_body() -> None:
    with _client() as client:
        # Group B re-audit is read-only and must succeed even with a stray body.
        response = client.post(
            "/api/acceptance/groups/b/run",
            json={"providers": ["deepseek"]},
        )
        assert response.status_code == 200
        assert response.json()["group_id"] == "b"
