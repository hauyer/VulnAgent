"""API boundary checks for the software-code audit entry point."""

from fastapi.testclient import TestClient

from vulnagent.api.app import create_app


def test_software_code_task_requires_local_authorization() -> None:
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/tasks",
            json={
                "target_path": "samples/local.c",
                "target_type": "source",
                "metadata": {"audit_domain": "software_code", "defensive_only": True},
            },
        )
    assert response.status_code == 403


def test_software_code_task_rejects_remote_paths() -> None:
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/tasks",
            json={
                "target_path": "https://example.com/source.c",
                "target_type": "source",
                "metadata": {
                    "audit_domain": "software_code",
                    "local_authorized": True,
                    "defensive_only": True,
                },
            },
        )
    assert response.status_code == 400


def test_authorized_local_software_code_task_is_created() -> None:
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/tasks",
            json={
                "target_path": "samples/local.c",
                "target_type": "source",
                "metadata": {
                    "audit_domain": "software_code",
                    "local_authorized": True,
                    "defensive_only": True,
                },
            },
        )
    assert response.status_code == 201
