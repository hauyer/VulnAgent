"""Controlled, authorized fuzz evidence through the V0.3 runtime."""

from pathlib import Path

import pytest

from vulnagent.bootstrap import build_v03_source_application
from vulnagent.contracts import EvidenceType, Target, TargetType, TaskStatus
from vulnagent.settings import Settings


@pytest.mark.asyncio
async def test_authorized_local_crash_reaches_verification(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text(
        "import sys\n\ndef marker():\n    return eval(input())\n"
        "\nif sys.stdin.buffer.read():\n    raise SystemExit(7)\n",
        encoding="utf-8",
    )
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "seed").write_bytes(b"crash")
    services = build_v03_source_application(
        settings=Settings(vulnagent_profile="v03-source")
    )
    task = services.task_manager.create_task(
        Target(
            target_id="controlled-fuzz-target",
            path=str(target),
            target_type=TargetType.SOURCE,
            metadata={
                "fuzz_authorized": True,
                "dynamic_validation": True,
                "seed_dir": str(seeds),
            },
        )
    )

    context = await services.orchestrator.run(task.task_id)

    assert context.task.status is TaskStatus.COMPLETED
    crash_evidence = [
        item for item in context.evidence
        if item.evidence_type is EvidenceType.CRASH_LOG
    ]
    assert crash_evidence
    crash_finding = next(
        item for item in context.findings if item.vulnerability_type == "fuzz_crash"
    )
    assert set(crash_finding.evidence_ids).intersection(
        item.evidence_id for item in crash_evidence
    )
    assert crash_finding.status.value == "confirmed"
    assert any(item.vulnerability_id == crash_finding.vulnerability_id for item in context.verifications)


@pytest.mark.asyncio
async def test_unauthorized_fuzz_never_executes(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text("raise SystemExit(9)\n", encoding="utf-8")
    from vulnagent.fuzz.engine import ControlledFuzzEngine
    from vulnagent.contracts import FuzzRequest

    result = await ControlledFuzzEngine().run(
        FuzzRequest(
            task_id="unauthorized-task",
            target_id="unauthorized-target",
            target_path=str(target),
            authorized=False,
        )
    )
    assert result.executed is False
    assert result.evidence == []
    assert result.metadata["reason"] == "target_not_authorized"
