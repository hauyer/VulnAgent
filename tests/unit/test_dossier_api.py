"""WP6 unit: research API (dossiers endpoints)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from vulnagent.api.app import create_app
from vulnagent.review import (
    DossierState,
    ExplorationLogEntry,
    ExplorationStage,
    ExploratorySession,
)


def _make_session() -> ExploratorySession:
    return ExploratorySession(
        session_id="api-test-1",
        target_id="unknown-target",
        target_kind="binary",
        authorization={"dynamic_run": True},
        practice_mode=True,
    )


def test_dossier_api_lifecycle() -> None:
    client = TestClient(create_app())
    session = _make_session()

    created = client.post("/api/dossiers", json=session.model_dump(mode="json"))
    assert created.status_code == 200
    assert created.json()["session_id"] == "api-test-1"

    entry = client.post(
        "/api/dossiers/api-test-1/entries",
        json=ExplorationLogEntry(
            stage=ExplorationStage.DISCOVERY,
            kind="tool_fact",
            detail="semgrep executed",
        ).model_dump(mode="json"),
    )
    assert entry.status_code == 200
    assert entry.json()["entries"] == 1

    # Practice mode: maintainer_contacted is allowed, acknowledged is not.
    ok = client.post(
        "/api/dossiers/api-test-1/state",
        params={"target_state": DossierState.MAINTAINER_CONTACTED.value},
    )
    assert ok.status_code == 200
    blocked = client.post(
        "/api/dossiers/api-test-1/state",
        params={"target_state": DossierState.ACKNOWLEDGED.value},
    )
    assert blocked.status_code == 422

    redacted = client.get("/api/dossiers/api-test-1/redacted")
    assert redacted.status_code == 200
    body = redacted.json()
    assert body["practice_mode"] is True
    assert "Nothing has been submitted" in body["disclosure_note"]


def test_dossier_api_missing_session_404() -> None:
    client = TestClient(create_app())
    assert client.get("/api/dossiers/nope/redacted").status_code == 404
    assert (
        client.post(
            "/api/dossiers/nope/state",
            params={"target_state": DossierState.SUBMITTED.value},
        ).status_code
        == 404
    )
