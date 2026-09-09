from fastapi.testclient import TestClient

from vulnagent.api.app import create_app


def test_health_and_task_workflow() -> None:
    with TestClient(create_app()) as client:
        assert client.get("/health").json() == {"status": "ok", "service": "vulnagent"}
        created = client.post("/tasks", json={"target_path": "sample.c", "target_type": "source"})
        assert created.status_code == 201
        task_id = created.json()["task_id"]
        run = client.post(f"/tasks/{task_id}/run")
        assert run.status_code == 200
        assert run.json()["status"] == "completed"
        assert client.get(f"/tasks/{task_id}").json()["task_id"] == task_id
        assert len(client.get(f"/tasks/{task_id}/findings").json()) >= 1
        events = client.get(f"/tasks/{task_id}/events").json()
        assert events[0]["event_type"] == "task_started"
        assert any(item["event_type"] == "evidence_added" for item in events)
        assert client.get(f"/api/tasks/{task_id}/trace").json() == events
        assert client.get(f"/api/tasks/{task_id}/evidence").status_code == 200
        report = client.get(f"/api/tasks/{task_id}/report")
        assert report.status_code == 200
        assert report.json()["task_id"] == task_id
        verifications = client.get(f"/api/tasks/{task_id}/verifications")
        assert verifications.status_code == 200
        assert isinstance(verifications.json(), list)


def test_task_trace_and_verifications_endpoints() -> None:
    with TestClient(create_app()) as client:
        # Non-existent task checks
        assert client.get("/tasks/non-existent-id/trace").status_code == 404
        assert client.get("/tasks/non-existent-id/verifications").status_code == 404
        assert client.get("/tasks/non-existent-id/findings").status_code == 404
        assert client.get("/tasks/non-existent-id/evidence").status_code == 404
        assert client.get("/tasks/non-existent-id/report").status_code == 404

        # Create and run
        created = client.post("/tasks", json={"target_path": "tests/fixtures/sample", "target_type": "source"})
        assert created.status_code == 201
        task_id = created.json()["task_id"]

        run_resp = client.post(f"/tasks/{task_id}/run")
        assert run_resp.status_code == 200

        # Query trace and verifications
        trace_resp = client.get(f"/tasks/{task_id}/trace")
        assert trace_resp.status_code == 200
        assert isinstance(trace_resp.json(), list)

        verif_resp = client.get(f"/tasks/{task_id}/verifications")
        assert verif_resp.status_code == 200
        assert isinstance(verif_resp.json(), list)


def test_frontend_static_serving() -> None:
    with TestClient(create_app()) as client:
        resp = client.get("/")
        assert resp.status_code == 200
        assert "VulnAgent" in resp.text
        assert "root" in resp.text

        # Verify bundled assets if built with Vite
        import re
        css_match = re.search(r'href="([^"]+\.css)"', resp.text)
        if css_match:
            css_path = css_match.group(1)
            css_resp = client.get(css_path)
            assert css_resp.status_code == 200
            assert len(css_resp.text) > 0

        js_match = re.search(r'src="([^"]+\.js)"', resp.text)
        if js_match:
            js_path = js_match.group(1)
            js_resp = client.get(js_path)
            assert js_resp.status_code == 200
            assert len(js_resp.text) > 0


