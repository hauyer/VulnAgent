"""Controlled PoC API generates only read-only confirmed-evidence replays."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from vulnagent.api.app import create_app
from vulnagent.poc import ControlledPocService, ControlledPocStore
from vulnagent.settings import Settings


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_controlled_poc_round_trip_is_confirmed_local_and_non_executing(
    tmp_path: Path,
) -> None:
    app = create_app(settings=Settings(_env_file=None, vulnagent_profile="v03-source"))
    app.state.controlled_poc = ControlledPocService(
        repository_root=REPOSITORY_ROOT,
        task_manager=app.state.task_manager,
        orchestrator=app.state.orchestrator,
        store=ControlledPocStore(
            tmp_path / "controlled-poc.json",
            tmp_path / "bundles",
        ),
    )

    with TestClient(app) as client:
        task = client.post(
            "/api/tasks",
            json={
                "target_path": "samples/source_demo/vulnerable.py",
                "target_type": "source",
                "language": "python",
            },
        ).json()
        task_id = task["task_id"]
        assert client.post(f"/api/tasks/{task_id}/run").status_code == 200
        confirmed = next(
            item
            for item in client.get(f"/api/tasks/{task_id}/findings").json()
            if item["status"] == "confirmed"
        )

        missing_ack = client.post(
            f"/api/tasks/{task_id}/poc",
            json={
                "vulnerability_id": confirmed["vulnerability_id"],
                "acknowledge_controlled_scope": False,
            },
        )
        assert missing_ack.status_code == 409

        generated = client.post(
            f"/api/tasks/{task_id}/poc",
            json={
                "vulnerability_id": confirmed["vulnerability_id"],
                "acknowledge_controlled_scope": True,
            },
        )
        assert generated.status_code == 201, generated.text
        bundle = generated.json()
        assert bundle["verification_status"] == "confirmed"
        assert bundle["code_kind"] == "evidence_replay"
        assert bundle["safety_profile"] == {
            "local_only": True,
            "target_execution": False,
            "network_access": False,
            "command_execution": False,
            "privilege_escalation": False,
            "persistence": False,
            "evasion": False,
        }
        lowered = bundle["code"].casefold()
        for forbidden in ("import socket", "import subprocess", "os.system", "requests."):
            assert forbidden not in lowered

        artifact = Path(bundle["artifact_path"])
        assert artifact.is_file()
        replay = subprocess.run(
            [sys.executable, str(artifact)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert replay.returncode == 0, replay.stderr
        replay_result = json.loads(replay.stdout)
        assert replay_result["ok"] is True
        assert replay_result["safety"] == {
            "target_executed": False,
            "network_used": False,
            "commands_run": False,
        }

        bundle_id = bundle["bundle_id"]
        assert client.get(f"/api/tasks/{task_id}/poc").json()[0]["bundle_id"] == bundle_id
        code_response = client.get(f"/api/tasks/{task_id}/poc/{bundle_id}/code")
        assert code_response.status_code == 200
        assert code_response.text == bundle["code"]

        refreshed_task = client.get(f"/api/tasks/{task_id}").json()
        assert bundle_id in refreshed_task["metadata"]["controlled_poc_bundle_ids"]
        report = client.get(f"/api/tasks/{task_id}/report").json()["content"]
        assert report["controlled_poc_bundles"][0]["bundle_id"] == bundle_id
        assert "code" not in report["controlled_poc_bundles"][0]


def test_controlled_poc_rejects_unconfirmed_findings(tmp_path: Path) -> None:
    app = create_app(settings=Settings(_env_file=None, vulnagent_profile="mock"))
    app.state.controlled_poc = ControlledPocService(
        repository_root=REPOSITORY_ROOT,
        task_manager=app.state.task_manager,
        orchestrator=app.state.orchestrator,
        store=ControlledPocStore(tmp_path / "index.json", tmp_path / "bundles"),
    )
    with TestClient(app) as client:
        task = client.post(
            "/api/tasks",
            json={
                "target_path": "samples/source_demo/vulnerable.py",
                "target_type": "source",
            },
        ).json()
        task_id = task["task_id"]
        assert client.post(f"/api/tasks/{task_id}/run").status_code == 200
        finding = client.get(f"/api/tasks/{task_id}/findings").json()[0]
        response = client.post(
            f"/api/tasks/{task_id}/poc",
            json={
                "vulnerability_id": finding["vulnerability_id"],
                "acknowledge_controlled_scope": True,
            },
        )
        assert response.status_code == 409
        assert "independently confirmed" in response.json()["detail"]
