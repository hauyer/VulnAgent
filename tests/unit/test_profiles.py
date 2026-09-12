"""Explicit composition-profile coverage."""

import pytest

from vulnagent.analyzers.source.audit import MultiLanguageSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.bootstrap import build_profile_application
from vulnagent.settings import Settings
from vulnagent.verification.evidence_verifier import EvidenceVerifier
from vulnagent.contracts import Target, TargetType, TaskStatus


def test_v03_source_profile_wires_real_source_and_verification() -> None:
    services = build_profile_application(
        Settings(vulnagent_profile="v03-source")
    )
    assert isinstance(services.capabilities.source_parser, SourceProjectParser)
    assert isinstance(services.capabilities.source_auditor, MultiLanguageSourceAuditor)
    assert isinstance(services.capabilities.verifier, EvidenceVerifier)


def test_mock_profile_remains_explicitly_available() -> None:
    services = build_profile_application(Settings(vulnagent_profile="mock"))
    assert services.capabilities.source_parser.__class__.__name__ == "MockSourceParser"


def test_unknown_profile_fails_fast() -> None:
    with pytest.raises(ValueError, match="Unsupported VULNAGENT_PROFILE"):
        build_profile_application(Settings(vulnagent_profile="unknown"))


@pytest.mark.asyncio
async def test_standard_info_logging_does_not_break_orchestration(caplog) -> None:
    caplog.set_level("INFO")
    services = build_profile_application(Settings(vulnagent_profile="mock"))
    task = services.task_manager.create_task(
        Target(target_id="logging-target", path="fixture", target_type=TargetType.SOURCE)
    )
    context = await services.orchestrator.run(task.task_id)
    assert context.task.status is TaskStatus.COMPLETED
