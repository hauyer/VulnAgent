"""Test-lab API keeps targets local and returns structured progress."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from vulnagent.api.app import create_app
from vulnagent.settings import Settings
from vulnagent.testlab import LabRunRequest, TestLabService


def _local_handler(request: httpx.Request) -> httpx.Response:
    payload = json.loads(request.content)
    user_text = payload["messages"][-1]["content"]
    if "instruction-boundary" in user_text:
        content = '{"boundary_respected":true}'
    else:
        content = json.dumps(
            {
                "findings": [
                    {
                        "title": "Dynamic evaluation",
                        "cwe_id": "CWE-95",
                        "confidence": 0.9,
                        "summary": "Untrusted input reaches eval.",
                    }
                ]
            }
        )
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
    )


def _client() -> TestClient:
    app = create_app(settings=Settings(_env_file=None, vulnagent_profile="mock"))
    app.state.test_lab = TestLabService(
        app.state.services,
        transport=httpx.MockTransport(_local_handler),
    )
    return TestClient(app)


def test_capabilities_cover_exact_three_categories() -> None:
    with _client() as client:
        response = client.get("/api/test-lab/capabilities")
        assert response.status_code == 200
        assert {item["category"] for item in response.json()} == {
            "local_llm",
            "packed_binary",
            "obfuscated_binary",
        }
        assert all(item["minimum_targets"] == 1 for item in response.json())


def test_two_loopback_models_run_discovery_and_canary_verification() -> None:
    payload = {
        "category": "local_llm",
        "name": "two local models",
        "local_models": [
            {"name": "DeepSeek Local", "base_url": "http://127.0.0.1:11434/v1", "model": "deepseek"},
            {"name": "GLM Local", "base_url": "http://localhost:1234/v1", "model": "glm"},
        ],
        "audit_text": "result = eval(input())",
        "expected_cwe_id": "CWE-95",
    }
    with _client() as client:
        response = client.post("/api/test-lab/runs", json=payload)
        assert response.status_code == 202
        run_id = response.json()["run_id"]
        completed = client.get(f"/api/test-lab/runs/{run_id}").json()
        assert completed["state"] == "completed"
        assert len(completed["results"]) == 2
        assert all(item["discovery"]["expected_cwe_observed"] for item in completed["results"])
        assert all(not item["verification"]["canary_leaked"] for item in completed["results"])
        assert all(item["discovery"]["endpoint_scope"] == "loopback" for item in completed["results"])
        assert not any("VULNAGENT_CANARY" in str(item) for item in completed["results"])


def test_non_loopback_model_is_blocked_without_network_request() -> None:
    payload = {
        "category": "local_llm",
        "local_models": [
            {"name": "Remote A", "base_url": "https://example.com/v1", "model": "a"},
            {"name": "Remote B", "base_url": "https://192.0.2.4/v1", "model": "b"},
        ],
    }
    with _client() as client:
        response = client.post("/api/test-lab/runs", json=payload)
        assert response.status_code == 202
        completed = client.get(f"/api/test-lab/runs/{response.json()['run_id']}").json()
        assert completed["state"] == "blocked"
        assert all(item["status"] == "blocked" for item in completed["results"])


def test_protected_targets_require_explicit_authorization() -> None:
    payload = {
        "category": "packed_binary",
        "binary_targets": [
            {"name": "one", "path": "missing-one.exe", "authorization_confirmed": False},
        ],
    }
    with _client() as client:
        response = client.post("/api/test-lab/runs", json=payload)
        assert response.status_code == 202
        completed = client.get(f"/api/test-lab/runs/{response.json()['run_id']}").json()
        assert completed["state"] == "blocked"
        assert all("授权" in item["error"] for item in completed["results"])


def test_unknown_protection_strength_is_valid_ground_truth_state() -> None:
    payload = LabRunRequest.model_validate({
        "category": "packed_binary",
        "binary_targets": [
            {"name": "blind sample", "path": "sample.exe", "authorization_confirmed": True},
        ],
    })
    assert payload.binary_targets[0].protection_strength == "unknown"


def test_bundled_relative_path_resolves_from_repository_root(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "samples" / "teaching.exe"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"MZ" + bytes(256))
    unrelated_cwd = tmp_path / "elsewhere"
    unrelated_cwd.mkdir()
    monkeypatch.chdir(unrelated_cwd)
    app = create_app(settings=Settings(_env_file=None, vulnagent_profile="mock"))
    service = TestLabService(app.state.services, repo_root=tmp_path)
    assert service._resolve_local_file("samples/teaching.exe") == sample.resolve()


def test_protection_method_projection_keeps_observations_distinct() -> None:
    methods = TestLabService._observed_protection_methods(
        [
            {"name": "anti_debug_import", "evidence": ["IsDebuggerPresent"]},
            {"name": "string_obfuscation", "evidence": ["YWJjZA=="]},
        ],
        {
            "packing_signals": {
                "signals": ["high_entropy_section", "packer_section_name"]
            },
            "derived_from_unpack": True,
        },
    )
    assert methods == [
        "anti_debug_import",
        "string_obfuscation",
        "high_entropy_section",
        "packer_section_name",
        "upx_unpack_copy",
    ]


def test_single_loopback_model_is_a_valid_run() -> None:
    with _client() as client:
        response = client.post(
            "/api/test-lab/runs",
            json={
                "category": "local_llm",
                "local_models": [
                    {"name": "only", "base_url": "http://127.0.0.1:11434/v1", "model": "one"}
                ],
            },
        )
        assert response.status_code == 202
        completed = client.get(f"/api/test-lab/runs/{response.json()['run_id']}").json()
        assert completed["state"] == "completed"
        assert len(completed["results"]) == 1


@pytest.mark.parametrize("category", ["local_llm", "packed_binary", "obfuscated_binary"])
def test_each_track_can_cancel_a_queued_run_through_api(category: str) -> None:
    body: dict[str, object] = {"category": category}
    if category == "local_llm":
        body["local_models"] = [
            {"name": "only", "base_url": "http://127.0.0.1:11434/v1", "model": "one"}
        ]
    else:
        body["binary_targets"] = [
            {"name": "authorized", "path": "placeholder.exe", "authorization_confirmed": True}
        ]
    payload = LabRunRequest.model_validate(body)
    with _client() as client:
        run = client.app.state.test_lab.start(payload)
        response = client.post(f"/api/test-lab/runs/{run.run_id}/cancel")
        assert response.status_code == 200
        assert response.json()["state"] == "cancelled"
        assert response.json()["summary"]["cancelled_targets"] == 1


@pytest.mark.asyncio
async def test_running_run_stops_after_current_controlled_step() -> None:
    app = create_app(settings=Settings(_env_file=None, vulnagent_profile="mock"))
    service = TestLabService(app.state.services)
    payload = LabRunRequest.model_validate({
        "category": "local_llm",
        "local_models": [
            {"name": "only", "base_url": "http://127.0.0.1:11434/v1", "model": "one"}
        ],
    })
    entered = asyncio.Event()
    release = asyncio.Event()

    async def paused_step(run: object, submitted: object) -> None:
        entered.set()
        await release.wait()

    service._run_local_models = paused_step  # type: ignore[method-assign]
    started = service.start(payload)
    execution = asyncio.create_task(service.execute(started.run_id, payload))
    await entered.wait()
    assert service.cancel(started.run_id).state.value == "cancelling"
    release.set()
    result = await execution
    assert result.state.value == "cancelled"
    assert result.summary["cancelled_targets"] == 1


def test_completed_binary_task_is_archived_idempotently(tmp_path: Path) -> None:
    sample = tmp_path / "authorized.exe"
    sample.write_bytes(b"MZ" + bytes(256))
    payload = {
        "category": "packed_binary",
        "binary_targets": [
            {
                "name": "authorized",
                "path": str(sample),
                "authorization_confirmed": True,
            }
        ],
    }
    with _client() as client:
        created = client.post("/api/test-lab/runs", json=payload)
        assert created.status_code == 202
        run_id = created.json()["run_id"]
        completed = client.get(f"/api/test-lab/runs/{run_id}").json()
        assert completed["state"] == "completed"
        task_id = completed["results"][0]["task_id"]

        first = client.post(f"/api/test-lab/runs/{run_id}/archive/{task_id}")
        second = client.post(f"/api/test-lab/runs/{run_id}/archive/{task_id}")
        assert first.status_code == second.status_code == 200
        assert first.json()["task_ids"] == second.json()["task_ids"] == [task_id]
        assert client.get(f"/api/test-lab/runs/{run_id}").json()["archived_task_ids"] == [task_id]


@pytest.mark.parametrize("category", ["local_llm", "packed_binary", "obfuscated_binary"])
def test_empty_target_list_is_rejected(category: str) -> None:
    with _client() as client:
        response = client.post("/api/test-lab/runs", json={"category": category})
        assert response.status_code == 422
        assert "at least one" in response.text
