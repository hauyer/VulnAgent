"""Human review annotations save, read back, and enrich report projection."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnagent.api.app import create_app
from vulnagent.review import ReviewAnnotationStore
from vulnagent.settings import Settings


def test_human_review_round_trip_and_report_projection(tmp_path: Path) -> None:
    app = create_app(settings=Settings(_env_file=None, vulnagent_profile="mock"))
    app.state.review_annotations = ReviewAnnotationStore(tmp_path / "reviews.json")
    with TestClient(app) as client:
        created = client.post(
            "/api/tasks",
            json={"target_path": "samples/source_demo", "target_type": "source"},
        ).json()
        task_id = created["task_id"]
        assert client.post(f"/api/tasks/{task_id}/run").status_code == 200
        finding_id = client.get(f"/api/tasks/{task_id}/findings").json()[0]["vulnerability_id"]

        saved = client.put(
            f"/api/tasks/{task_id}/findings/{finding_id}/review",
            json={
                "decision": "needs_followup",
                "note": "补充动态证据后再确认。",
                "reviewer": "student",
            },
        )
        assert saved.status_code == 200
        assert saved.json()["vulnerability_id"] == finding_id

        reviews = client.get(f"/api/tasks/{task_id}/reviews").json()
        assert len(reviews) == 1
        assert reviews[0]["note"] == "补充动态证据后再确认。"

        report = client.get(f"/api/tasks/{task_id}/report").json()["content"]
        assert report["human_review"]["annotation_count"] == 1
        assert report["course_acceptance_summary"]["excluded_scope"] == [
            "priority-8-network-filesystem-isolation",
            "priority-9-cross-process-agent-checkpoint",
        ]
