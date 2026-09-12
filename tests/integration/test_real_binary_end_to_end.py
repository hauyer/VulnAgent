"""Non-executing binary acceptance chain using a deterministic PE fixture."""

from pathlib import Path

import pytest

from tests.binary_reverse.test_static import make_pe, make_pe_stdio_call
from vulnagent.bootstrap import (
    build_application,
    build_v03_source_application,
    build_v03_source_capabilities,
)
from vulnagent.contracts import (
    BinaryAnalysisResult,
    EvidenceType,
    Target,
    TargetType,
    TaskStatus,
)
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
        assert risky[0].location.binary_address is not None
        assert risky[0].metadata["locator_kind"] == "decoded_callsite"
        assert risky[0].metadata["locator_precision"] == "instruction_address"
        assert any(
            item.evidence_type is EvidenceType.DISASSEMBLY
            and item.evidence_id in risky[0].evidence_ids
            for item in context.evidence
        )


class _AuthorizedReverseFixture:
    async def analyze(self, request, **options):
        assert options == {"authorized": True, "auto_unpack": True}
        return BinaryAnalysisResult(
            task_id=request.task_id,
            target_id=request.target_id,
            path=request.path,
            file_format="PE",
            architecture="x86_64",
            functions=[{"name": "check_license", "address": 0x401000, "size": 48}],
            cfg={"0x401000": ["0x401020"]},
            metadata={
                "sha256": "0" * 64,
                "reverse_tool": {
                    "source": "test-offline-decompiler",
                    "functions": [{"name": "check_license", "address": 0x401000, "size": 48}],
                    "cfg": {"0x401000": ["0x401020"]},
                    "pseudocode": {
                        "0x401000": "int check_license(char *value) { strcpy(buffer, value); return verify_password(value); }",
                    },
                },
                "tool_runs": [
                    {
                        "tool": "radare2",
                        "status": "ok",
                        "executed": True,
                        "facts": {
                            "functions": [{"address": 0x401000}],
                            "cfg": {"0x401000": ["0x401020"]},
                            "pseudocode": {"0x401000": "bounded fixture"},
                        },
                    }
                ],
                "analysis_plan": {
                    "steps": [
                        {"stage": "structural_parse", "status": "completed"},
                        {"stage": "unpack", "status": "completed"},
                        {"stage": "decompile", "status": "completed"},
                        {"stage": "semantic_logic", "status": "scheduled"},
                        {"stage": "vulnerability_rules", "status": "scheduled"},
                        {"stage": "independent_verification", "status": "scheduled"},
                    ]
                },
                "workflow": {"target_executed": False, "unpacked_artifact_created": True},
            },
        )


@pytest.mark.parametrize(
    "target_metadata",
    [
        {
            "test_lab_category": "packed_binary",
            "authorization_confirmed": True,
            "protection": "UPX + custom VM",
        },
        {
            "test_lab_category": "custom_binary",
            "authorization_confirmed": True,
            "reverse_analysis_enabled": True,
        },
    ],
)
async def test_authorized_reverse_artifacts_reach_workbench_and_rules(
    target_metadata: dict[str, object],
) -> None:
    services = build_application(
        build_v03_source_capabilities(),
        settings=Settings(vulnagent_profile="v03-source", binary_reverse_enabled=False),
        binary_reverse_workflow=_AuthorizedReverseFixture(),  # type: ignore[arg-type]
    )
    task = services.task_manager.create_task(
        Target(
            target_id="authorized-packed-target",
            path="authorized-fixture.exe",
            target_type=TargetType.BINARY,
            metadata=target_metadata,
        )
    )

    context = await services.orchestrator.run(task.task_id)

    assert any(item.evidence_type is EvidenceType.DISASSEMBLY for item in context.evidence)
    assert any(item.evidence_type is EvidenceType.CFG_PATH for item in context.evidence)
    assert any(item.evidence_type is EvidenceType.CALL_PATH for item in context.evidence)
    logic = next(item for item in context.evidence if item.source == "binary_logic")
    assert any(item["category"] == "authentication" for item in logic.data["locations"])
    reverse_summary = next(
        item
        for item in context.evidence
        if item.source == "binary_reverse" and item.evidence_type is EvidenceType.TOOL_RESULT
    )
    if target_metadata.get("protection"):
        assert reverse_summary.data["declared_protection"] == "UPX + custom VM"
        assert reverse_summary.data["protection_category"] == "packed_binary"
        assert "upx_unpack_copy" in reverse_summary.data["observed_protection_methods"]
    finding = next(item for item in context.findings if item.vulnerability_type == "risky_binary_api")
    assert finding.metadata["signal_basis"] == "decompiled_pseudocode"
    assert finding.location.binary_address == "0x401000"
    assert finding.metadata["locator_kind"] == "decompiled_function"
    assert finding.metadata["locator_precision"] == "function_address"
