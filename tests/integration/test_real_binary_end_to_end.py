"""Non-executing binary acceptance chain using a deterministic PE fixture."""

from pathlib import Path

import pytest

from tests.binary_reverse.test_static import make_pe, make_pe_stdio_call
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
    assert any(item.source == "binary_logic" for item in context.evidence)
    plan = next(message for message in context.messages if message.message_type.value == "plan")
    assert {"binary.inspect", "binary.logic", "binary.obfuscation"}.issubset(
        plan.payload["requested_capabilities"]
    )


@pytest.mark.parametrize(("unbounded", "finding_expected"), [(True, True), (False, False)])
async def test_callsite_semantics_distinguish_unbounded_and_bounded_wrappers(
    tmp_path: Path,
    unbounded: bool,
    finding_expected: bool,
) -> None:
    pytest.importorskip("capstone")
    target = tmp_path / "stdio-wrapper.exe"
    target.write_bytes(make_pe_stdio_call(unbounded=unbounded))
    services = build_v03_source_application(
        settings=Settings(vulnagent_profile="v03-source")
    )
    task = services.task_manager.create_task(
        Target(
            target_id="stdio-wrapper",
            path=str(target),
            target_type=TargetType.BINARY,
        )
    )

    context = await services.orchestrator.run(task.task_id)
    risky = [
        item for item in context.findings
        if item.vulnerability_type == "risky_binary_api"
    ]

    assert bool(risky) is finding_expected
    if finding_expected:
        assert risky[0].metadata["signal_basis"] == "pe_x64_callsite_semantics"
        assert any(
            item.evidence_type is EvidenceType.DISASSEMBLY
            and item.evidence_id in risky[0].evidence_ids
            for item in context.evidence
        )
