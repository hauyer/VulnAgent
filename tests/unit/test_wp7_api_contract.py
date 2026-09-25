"""WP7: API contract tests for the research/read-only endpoints the UI uses.

The UI consumes existing core endpoints (tasks, trace, findings, evidence,
verifications, reports) plus the read-only research API (experiments,
dossiers). These tests pin the contract: paths exist, path traversal is
blocked, and the built frontend mounts without shadowing /api.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from vulnagent.api.app import create_app

REQUIRED_API_PATHS = {
    "/api/tasks",
    "/api/tasks/{task_id}",
    "/api/tasks/{task_id}/run",
    "/api/tasks/{task_id}/trace",
    "/api/tasks/{task_id}/findings",
    "/api/tasks/{task_id}/evidence",
    "/api/tasks/{task_id}/verifications",
    "/api/tasks/{task_id}/report.html",
    "/api/experiments",
    "/api/experiments/{experiment_id}",
    "/api/dossiers/{session_id}/redacted",
}


def test_openapi_exposes_ui_contract() -> None:
    schema = TestClient(create_app()).get("/openapi.json").json()
    paths = set(schema["paths"])
    missing = REQUIRED_API_PATHS - paths
    assert not missing, f"missing contract paths: {sorted(missing)}"


def test_experiments_traversal_is_blocked() -> None:
    client = TestClient(create_app())
    for attempt in ("..%2F..%2Fsecret", "..", "a/b", "wp4-libfuzzer%00"):
        response = client.get(f"/api/experiments/{attempt}")
        assert response.status_code == 404, f"traversal {attempt} not blocked"


def test_built_frontend_served_without_shadowing_api() -> None:
    """The production UI is mounted from dist/ when it exists; /api still wins."""
    from vulnagent.api.app import _mount_built_frontend
    from fastapi import FastAPI

    app = FastAPI()

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # If dist/ is missing the mount is optional (dev mode via Vite proxy).
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    mounted = _mount_built_frontend(app, root)
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        if mounted:
            assert client.get("/").status_code == 200
            assert "VulnAgent" in client.get("/").text
