import pytest

from vulnagent.core.models import Target, TargetType, TaskStatus, VulnerabilityStatus
from vulnagent.core.orchestrator import Orchestrator
from vulnagent.core.task_manager import InMemoryTaskManager
from vulnagent.evidence.store import InMemoryEvidenceStore


@pytest.mark.parametrize("target_type", [TargetType.SOURCE, TargetType.BINARY])
async def test_mock_pipeline_completes_for_supported_targets(target_type: TargetType) -> None:
    manager = InMemoryTaskManager()
    evidence_store = InMemoryEvidenceStore()
    orchestrator = Orchestrator(manager, evidence_store)
    task = manager.create_task(Target(target_id="target", path="fixture", target_type=target_type))
    context = await orchestrator.run(task.task_id)
    assert context.task.status is TaskStatus.COMPLETED
    assert context.findings
    assert context.findings[0].status is VulnerabilityStatus.UNCERTAIN
    assert context.evidence
    assert evidence_store.list_by_task(task.task_id)
    assert any(message.sender == "verification" for message in context.messages)

