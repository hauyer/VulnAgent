"""S6 (work-package F): read-only endpoints + uniform error envelope tests.

Covers:
  * enhanced experiment detail (manifest digest, metrics state ready/pending)
  * GET /api/experiments/{id}/findings (status filter, pagination, no GT leak)
  * GET /api/experiments/{id}/metrics (three denominators; pending before finalize)
  * enhanced task trace (detail=true: route reasons, evidence ids, redaction,
    no ground truth)
  * uniform error envelope on 404/validation errors
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from vulnagent.api.app import create_app

_REPO = Path(__file__).resolve().parents[2]


def _client():
    return TestClient(create_app())


def test_experiment_detail_manifest_digest_and_metrics_state() -> None:
    exp = "p1c-wasm3-surface"  # real archive with manifest + metrics
    payload = _client().get(f"/api/experiments/{exp}").json()
    assert payload["experiment_id"] == exp
    assert payload["metrics_state"] in {"ready", "pending"}
    manifest = payload["manifest"]
    assert manifest["protocol"]
    assert manifest["target_revision"] == "ea6ad909139a22d224c5d77796421d6ffa91b05f"
    assert manifest["source_sha256"]
    assert payload["candidate_count"] >= 1
    assert payload["verification_count"] >= 1


def test_experiment_metrics_pending_before_finalize() -> None:
    # p1c-wasm3-surface metrics.json carries a candidate but no verdict numbers
    # -> must be reported as pending, not half-answered.
    payload = _client().get("/api/experiments/p1c-wasm3-surface/metrics").json()
    assert payload["metrics_state"] == "pending"
    assert "message" in payload


def test_experiment_metrics_ready_with_verdicts() -> None:
    # exploitgym-blind metrics.json contains tp/fp/fn/precision -> ready.
    payload = _client().get("/api/experiments/exploitgym-blind/metrics").json()
    assert payload["metrics_state"] == "ready"
    assert set(payload["denominators"]) == {"case", "candidate", "unique_root_cause"}
    assert set(payload["verdicts"]) == {"tp", "fp", "fn", "tn"}


def test_findings_list_filter_and_pagination() -> None:
    client = _client()
    base = client.get("/api/experiments/p1c-wasm3-surface/findings").json()
    assert base["total"] >= 1
    assert all("candidate_id" in f for f in base["findings"])
    assert all("verification_status" in f for f in base["findings"])
    assert all("cwe_id" in f for f in base["findings"])
    assert all("evidence_ids" in f for f in base["findings"])
    # status filter
    filtered = client.get(
        "/api/experiments/p1c-wasm3-surface/findings", params={"status": "confirmed"}
    ).json()
    assert all(f["verification_status"] == "confirmed" for f in filtered["findings"])
    # pagination shape
    paged = client.get(
        "/api/experiments/p1c-wasm3-surface/findings", params={"limit": 1, "offset": 0}
    ).json()
    assert len(paged["findings"]) <= 1
    assert paged["offset"] == 0 and paged["limit"] == 1


def test_findings_never_leak_ground_truth() -> None:
    payload = _client().get("/api/experiments/exploitgym-blind/findings").json()
    for finding in payload["findings"]:
        assert "gt" not in str(finding).lower()
        assert "ground_truth" not in finding


def test_trace_detail_redacts_and_excludes_gt() -> None:
    sample = _REPO / "samples" / "source_demo"
    with TestClient(create_app()) as client:
        created = client.post(
            "/tasks", json={"target_path": str(sample), "target_type": "source"}
        ).json()
        task_id = created["task_id"]
        client.post(f"/tasks/{task_id}/run")
        # default: plain list (backward compatible)
        plain = client.get(f"/api/tasks/{task_id}/trace").json()
        assert isinstance(plain, list)
        # detail mode: summary + redaction + no GT
        detailed = client.get(f"/api/tasks/{task_id}/trace", params={"detail": "true"}).json()
        assert detailed["ground_truth_included"] is False
        assert detailed["summary"]["task_id"] == task_id
        assert detailed["summary"]["event_count"] == len(plain)
        assert isinstance(detailed["events"], list)
        for event in detailed["events"]:
            assert "ground_truth" not in event
            for value in event["payload"].values():
                if isinstance(value, str) and len(value) > 128:
                    assert value.startswith("[redacted:")


def test_error_envelope_on_404_and_validation() -> None:
    client = _client()
    resp = client.get("/api/experiments/nonexistent-id-xyz")
    assert resp.status_code == 404
    body = resp.json()
    assert body["code"] == "NOT_FOUND"
    assert body["message"]
    assert body["retryable"] is False
    assert "detail" in body  # legacy alias preserved
    # validation error gets the envelope too
    resp = client.get("/api/experiments/p1c-wasm3-surface/findings", params={"limit": 0})
    assert resp.status_code == 422
    assert resp.json()["code"] == "BAD_REQUEST"


def test_openapi_exposes_new_subpaths() -> None:
    paths = set(_client().get("/openapi.json").json()["paths"])
    for required in (
        "/api/experiments/{experiment_id}/findings",
        "/api/experiments/{experiment_id}/metrics",
    ):
        assert required in paths


def test_create_task_validates_protocol_and_manifest_reference() -> None:
    client = _client()
    # unknown protocol rejected
    resp = client.post(
        "/tasks",
        json={
            "target_path": "samples/source_demo",
            "target_type": "project",
            "metadata": {"experiment_protocol": "no_such_protocol"},
        },
    )
    assert resp.status_code == 400
    assert "experiment_protocol" in resp.json()["detail"]
    # manifest reference requires protocol
    resp = client.post(
        "/tasks",
        json={
            "target_path": "samples/source_demo",
            "target_type": "project",
            "metadata": {"target_manifest_id": "opaque-x"},
        },
    )
    assert resp.status_code == 400
    assert "requires experiment_protocol" in resp.json()["detail"]
    # valid combination accepted
    resp = client.post(
        "/tasks",
        json={
            "target_path": "samples/source_demo",
            "target_type": "project",
            "metadata": {
                "experiment_protocol": "external_unknown",
                "target_manifest_id": "opaque-x",
            },
        },
    )
    assert resp.status_code == 201
    assert resp.json()["metadata"]["target_manifest_id"] == "opaque-x"


def test_run_writes_run_id_into_metadata() -> None:
    sample = _REPO / "samples" / "source_demo"
    with TestClient(create_app()) as client:
        created = client.post(
            "/tasks", json={"target_path": str(sample), "target_type": "source"}
        ).json()
        task_id = created["task_id"]
        assert "run_id" not in created["metadata"]
        ran = client.post(f"/tasks/{task_id}/run").json()
        assert ran["metadata"]["run_id"].startswith("run-")
        # the recorded run id stays stable afterwards (GET, not a second run)
        fetched = client.get(f"/tasks/{task_id}").json()
        assert fetched["metadata"]["run_id"] == ran["metadata"]["run_id"]
