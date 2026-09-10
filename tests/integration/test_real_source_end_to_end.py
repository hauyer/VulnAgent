"""V0.3 real source chain through public capability and API boundaries."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnagent.api.app import create_app
from vulnagent.bootstrap import build_v03_source_application
from vulnagent.contracts import EvidenceType, Target, TargetType, TaskStatus
from vulnagent.settings import Settings


@pytest.mark.asyncio
async def test_real_source_end_to_end(tmp_path: Path) -> None:
    (tmp_path / "vulnerable.py").write_text(
        "import os\n\ndef run():\n    value = input()\n    os.system(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "safe.py").write_text(
        "import subprocess\n\ndef run(value):\n"
        "    return subprocess.run(['echo', value], shell=False)\n",
        encoding="utf-8",
    )
    services = build_v03_source_application(
        settings=Settings(vulnagent_profile="v03-source")
    )
    task = services.task_manager.create_task(
        Target(
            target_id="real-source-target",
            path=str(tmp_path),
            target_type=TargetType.SOURCE,
        )
    )

    context = await services.orchestrator.run(task.task_id)

    assert context.task.status is TaskStatus.COMPLETED
    assert len(context.findings) == 1
    finding = context.findings[0]
    assert finding.producer == "PythonSourceAuditor"
    assert finding.status.value == "confirmed"
    evidence_types = {
        item.evidence_type for item in context.evidence
        if item.evidence_id in finding.evidence_ids
    }
    assert EvidenceType.SOURCE_LOCATION in evidence_types
    assert EvidenceType.CODE_SNIPPET in evidence_types
    assert EvidenceType.TAINT_PATH in evidence_types
    assert EvidenceType.VERIFICATION_RESULT in evidence_types
    assert context.verifications[0].status.value == "confirmed"
    assert context.reports[0].metadata["input_mode"] == "real"
    assert context.reports[0].content["summary"]["finding_count"] == 1
    assert any(message.sender == "reviewer" for message in context.messages)


def test_fastapi_real_source_resources(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\n\ndef run():\n    os.system(input())\n",
        encoding="utf-8",
    )
    settings = Settings(vulnagent_profile="v03-source")
    with TestClient(create_app(settings=settings)) as client:
        created = client.post(
            "/api/tasks",
            json={"target_path": str(tmp_path), "target_type": "source"},
        )
        assert created.status_code == 201
        task_id = created.json()["task_id"]
        assert client.post(f"/api/tasks/{task_id}/run").status_code == 200
        assert client.get(f"/api/tasks/{task_id}").json()["status"] == "completed"
        assert client.get(f"/api/tasks/{task_id}/findings").json()[0]["status"] == "confirmed"
        assert client.get(f"/api/tasks/{task_id}/evidence").json()
        assert client.get(f"/api/tasks/{task_id}/verifications").json()[0]["status"] == "confirmed"
        assert client.get(f"/api/tasks/{task_id}/trace").json()
        assert client.get(f"/api/tasks/{task_id}/report").json()["metadata"]["input_mode"] == "real"
