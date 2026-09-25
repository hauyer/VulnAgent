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

    # Practice mode: demonstration advance only moves simulated_state; the
    # real state stays draft and is never presented as maintainer_contacted.
    ok = client.post(
        "/api/dossiers/api-test-1/state",
        params={"target_state": DossierState.MAINTAINER_CONTACTED.value},
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["state"] == DossierState.DRAFT.value
    assert body["simulated_state"] == DossierState.MAINTAINER_CONTACTED.value
    # A later demonstration step is only allowed along legal simulated edges.
    blocked = client.post(
        "/api/dossiers/api-test-1/state",
        params={"target_state": DossierState.ACKNOWLEDGED.value},
    )
    assert blocked.status_code == 422

    redacted = client.get("/api/dossiers/api-test-1/redacted")
    assert redacted.status_code == 200
    body = redacted.json()
    assert body["practice_mode"] is True
    assert body["state"] == DossierState.DRAFT.value
    assert body["simulated_state"] == DossierState.MAINTAINER_CONTACTED.value
    assert "Nothing has been submitted" in body["disclosure_note"]


def test_dossier_api_real_mode_requires_receipt() -> None:
    client = TestClient(create_app())
    session = ExploratorySession(
        session_id="api-real-1",
        target_id="unknown-target",
        target_kind="binary",
        authorization={"dynamic_run": False},
        practice_mode=False,
    )
    assert client.post("/api/dossiers", json=session.model_dump(mode="json")).status_code == 200

    # Without a valid receipt the real state machine refuses the advance.
    refused = client.post(
        "/api/dossiers/api-real-1/state",
        params={"target_state": DossierState.SUBMITTED.value},
    )
    assert refused.status_code == 422

    # A kind=none receipt is not valid either.
    client.post(
        "/api/dossiers/api-real-1/receipt",
        json={"kind": "none", "reference": "", "note": "no contact"},
    )
    assert (
        client.post(
            "/api/dossiers/api-real-1/state",
            params={"target_state": DossierState.MAINTAINER_CONTACTED.value},
        ).status_code
        == 422
    )

    # A real ticket receipt with reference advances the machine.
    client.post(
        "/api/dossiers/api-real-1/receipt",
        json={"kind": "ticket", "reference": "T-42", "note": "maintainer replied"},
    )
    advanced = client.post(
        "/api/dossiers/api-real-1/state",
        params={"target_state": DossierState.MAINTAINER_CONTACTED.value},
    )
    assert advanced.status_code == 200
    assert advanced.json()["state"] == DossierState.MAINTAINER_CONTACTED.value


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
