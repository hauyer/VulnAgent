"""SQLite repository adapter round-trip and restart behavior."""

from pathlib import Path

import pytest

from vulnagent.bootstrap import build_profile_application
from vulnagent.contracts import (
    AnalysisContext,
    Evidence,
    EvidenceType,
    Target,
    TargetType,
    TaskStatus,
)
from vulnagent.settings import Settings
from vulnagent.storage.sqlite import SQLiteRepository


def test_sqlite_repository_round_trips_all_aggregate_types(tmp_path: Path) -> None:
    path = tmp_path / "state" / "vulnagent.db"
    first = SQLiteRepository(path)
    task = first.create_task(
        Target(target_id="target", path="sample.py", target_type=TargetType.SOURCE)
    )
    task = first.update_task(
        task.task_id,
        status=TaskStatus.PROFILING,
        metadata={"phase": "started"},
    )
    evidence = Evidence(
        evidence_id="evidence-1",
        task_id=task.task_id,
        evidence_type=EvidenceType.TOOL_RESULT,
        source="test",
        description="durable evidence",
        data={"finding_ids": ["finding-1"]},
        reliability=0.8,
        created_by="test",
    )
    first.save(evidence)
    first.save_context(AnalysisContext(task=task, evidence=[evidence]))

    reopened = SQLiteRepository(path)

    assert reopened.get_task(task.task_id) == task
    assert reopened.list_tasks() == [task]
    assert reopened.get("evidence-1") == evidence
    assert reopened.list_by_task(task.task_id) == [evidence]
    assert reopened.list_by_finding("finding-1") == [evidence]
    restored = reopened.get_context(task.task_id)
    assert restored is not None
    assert restored.task == task
    assert restored.evidence == [evidence]


@pytest.mark.asyncio
async def test_profile_services_restore_completed_context_after_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "vulnagent.db"
    settings = Settings(
        vulnagent_profile="mock",
        storage_backend="sqlite",
        sqlite_path=str(database),
    )
    first = build_profile_application(settings)
    task = first.task_manager.create_task(
        Target(
            target_id="restart-target",
            path="controlled.py",
            target_type=TargetType.SOURCE,
        )
    )
    completed = await first.orchestrator.run(task.task_id)
    assert completed.task.status is TaskStatus.COMPLETED

    reopened = build_profile_application(settings)
    restored_task = reopened.task_manager.get_task(task.task_id)
    restored_context = reopened.orchestrator.get_context(task.task_id)

    assert restored_task is not None
    assert restored_task.status is TaskStatus.COMPLETED
    assert restored_context is not None
    assert restored_context.findings
    assert restored_context.reports
    assert reopened.evidence_store.list_by_task(task.task_id)


def test_unknown_storage_backend_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported STORAGE_BACKEND"):
        build_profile_application(
            Settings(vulnagent_profile="mock", storage_backend="remote-magic")
        )
