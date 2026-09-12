"""Custom acceptance batches link models, tasks, files and reports."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnagent.acceptance import AcceptanceBatchStore
from vulnagent.api.app import create_app
from vulnagent.settings import Settings


def _completed_task(
    client: TestClient,
    *,
    path: str,
    target_type: str,
    metadata: dict[str, object],
) -> str:
    created = client.post(
        "/api/tasks",
        json={
            "target_path": path,
            "target_type": target_type,
            "file_format": "PE" if target_type == "binary" else None,
            "metadata": metadata,
        },
    )
    assert created.status_code == 201, created.text
    task_id = created.json()["task_id"]
    executed = client.post(f"/api/tasks/{task_id}/run")
    assert executed.status_code == 200, executed.text
    assert executed.json()["status"] == "completed"
    return task_id


def test_custom_batch_links_tasks_files_models_and_reports(tmp_path: Path) -> None:
    app = create_app(settings=Settings(_env_file=None, vulnagent_profile="mock"))
    app.state.acceptance_batches = AcceptanceBatchStore(tmp_path / "batches.json")

    with TestClient(app) as client:
        model_task = _completed_task(
            client,
            path="ollama-local/demo-model",
            target_type="archive",
            metadata={"model_name": "demo-model"},
        )
        # The archive endpoint normally sets task-level source metadata. Mirror
        # that durable fact without changing the frozen Task schema.
        app.state.task_manager.update_task(
            model_task,
            metadata={
                "source": "llm_vulnerability_scanner",
                "model_name": "demo-model",
            },
        )
        packed = [
            _completed_task(
                client,
                path=f"artifacts/uploads/packed-{index}.exe",
                target_type="binary",
                metadata={
                    "test_lab_category": "packed_binary",
                    "expected_sha256": f"packed-sha-{index}",
                    "protection": f"packed-method-{index}",
                },
            )
            for index in range(2)
        ]
        obfuscated = [
            _completed_task(
                client,
                path=f"artifacts/uploads/obfuscated-{index}.exe",
                target_type="binary",
                metadata={
                    "test_lab_category": "obfuscated_binary",
                    "expected_sha256": f"obfuscated-sha-{index}",
                    "protection": f"obfuscation-method-{index}",
                },
            )
            for index in range(2)
        ]

        created = client.post(
            "/api/acceptance/batches",
            json={
                "name": "答辩自定义批次",
                "model_names": ["demo-model"],
                "packed_task_ids": packed,
                "obfuscated_task_ids": obfuscated,
            },
        )
        assert created.status_code == 201, created.text
        batch = created.json()
        assert batch["state"] == "completed"
        assert batch["completed_groups"] == 3
        assert batch["model_task_ids"] == [model_task]
        assert len(batch["task_links"]) == 5
        assert all(item["report_available"] for item in batch["task_links"])
        assert all(item["report_links"]["html"] for item in batch["task_links"])
        packed_links = [item for item in batch["task_links"] if item["group_id"] == "b"]
        assert [item["declared_protection"] for item in packed_links] == [
            "packed-method-0",
            "packed-method-1",
        ]
        assert all(isinstance(item["observed_protection_methods"], list) for item in packed_links)
        assert all(group["metric_status"] == "not_evaluated" for group in batch["groups"])

        batch_id = batch["batch_id"]
        linked_task = client.get(f"/api/tasks/{packed[0]}").json()
        assert batch_id in linked_task["metadata"]["acceptance_batch_ids"]

        report = client.get(f"/api/tasks/{packed[0]}/report")
        assert report.status_code == 200
        report_batches = report.json()["content"]["acceptance_batches"]
        assert [item["batch_id"] for item in report_batches] == [batch_id]
        assert report.json()["content"]["task"]["metadata"][
            "acceptance_batch_ids"
        ] == [batch_id]

        listed = client.get("/api/acceptance/batches").json()
        assert listed[0]["batch_id"] == batch_id
        assert client.get(f"/api/acceptance/batches/{batch_id}").status_code == 200


def test_custom_batch_rejects_wrong_category_and_too_few_distinct_tasks(
    tmp_path: Path,
) -> None:
    app = create_app(settings=Settings(_env_file=None, vulnagent_profile="mock"))
    app.state.acceptance_batches = AcceptanceBatchStore(tmp_path / "batches.json")
    with TestClient(app) as client:
        wrong = client.post(
            "/api/tasks",
            json={
                "target_path": "wrong.exe",
                "target_type": "binary",
                "metadata": {"test_lab_category": "obfuscated_binary"},
            },
        ).json()["task_id"]
        another_wrong = client.post(
            "/api/tasks",
            json={
                "target_path": "another-wrong.exe",
                "target_type": "binary",
                "metadata": {"test_lab_category": "obfuscated_binary"},
            },
        ).json()["task_id"]
        valid_obfuscated = [
            client.post(
                "/api/tasks",
                json={
                    "target_path": f"obf-{index}.exe",
                    "target_type": "binary",
                    "metadata": {"test_lab_category": "obfuscated_binary"},
                },
            ).json()["task_id"]
            for index in range(2)
        ]
        response = client.post(
            "/api/acceptance/batches",
            json={
                "name": "invalid",
                "model_names": ["demo"],
                "packed_task_ids": [wrong, another_wrong],
                "obfuscated_task_ids": valid_obfuscated,
            },
        )
        assert response.status_code == 400
        assert "non-packed" in response.json()["detail"]

        too_few = client.post(
            "/api/acceptance/batches",
            json={
                "name": "invalid-count",
                "model_names": ["demo"],
                "packed_task_ids": [wrong],
                "obfuscated_task_ids": valid_obfuscated,
            },
        )
        assert too_few.status_code == 422
