from datetime import datetime

import pytest
from pydantic import ValidationError

from vulnagent.core.models import AgentResult, Evidence, EvidenceType, TargetType, VulnerabilityCandidate


def test_enums_have_expected_values() -> None:
    assert TargetType.SOURCE.value == "source"
    assert EvidenceType.VERIFICATION_RESULT.value == "verification_result"


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_confidence_range(confidence: float) -> None:
    with pytest.raises(ValidationError):
        VulnerabilityCandidate(vulnerability_id="v", task_id="t", title="x", vulnerability_type="x", description="x", target_id="target", source_agent="test", confidence=confidence)


@pytest.mark.parametrize("reliability", [-0.1, 1.1])
def test_reliability_range(reliability: float) -> None:
    with pytest.raises(ValidationError):
        Evidence(evidence_id="e", task_id="t", evidence_type=EvidenceType.TOOL_RESULT, source="test", description="x", reliability=reliability, created_by="test")


def test_mutable_defaults_are_not_shared() -> None:
    first = AgentResult(agent_name="one")
    second = AgentResult(agent_name="two")
    first.artifacts.append("x")
    assert second.artifacts == []


def test_default_datetime_is_timezone_aware() -> None:
    evidence = Evidence(evidence_id="e", task_id="t", evidence_type=EvidenceType.TOOL_RESULT, source="test", description="x", reliability=0.5, created_by="test")
    assert isinstance(evidence.created_at, datetime)
    assert evidence.created_at.tzinfo is not None

