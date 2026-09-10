"""Non-executing binary acceptance chain using a deterministic PE fixture."""

from pathlib import Path

import pytest

from tests.binary_reverse.test_static import make_pe
from vulnagent.bootstrap import build_v03_source_application
from vulnagent.contracts import EvidenceType, Target, TargetType, TaskStatus
from vulnagent.settings import Settings


@pytest.mark.asyncio
async def test_real_binary_signal_reaches_verification_and_report(tmp_path: Path) -> None:
    image = bytearray(make_pe())
    image[0x280:0x287] = b"strcpy\0"
    target = tmp_path / "sample.exe"
    target.write_bytes(image)
    services = build_v03_source_application(
        settings=Settings(vulnagent_profile="v03-source")
    )
    task = services.task_manager.create_task(
        Target(
            target_id="real-binary-target",
            path=str(target),
            target_type=TargetType.BINARY,
        )
    )

    context = await services.orchestrator.run(task.task_id)

    assert context.task.status is TaskStatus.COMPLETED
    finding = next(
        item for item in context.findings
        if item.vulnerability_type == "risky_binary_api"
    )
    assert finding.metadata["mock"] is False
    assert finding.status.value == "uncertain"
    assert any(
        item.evidence_type is EvidenceType.BINARY_ADDRESS
        and item.evidence_id in finding.evidence_ids
        for item in context.evidence
    )
    assert context.verifications[0].status.value == "uncertain"
    assert context.reports[0].metadata["input_mode"] == "real"
    assert context.reports[0].content["summary"]["finding_count"] == 1
