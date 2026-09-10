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
