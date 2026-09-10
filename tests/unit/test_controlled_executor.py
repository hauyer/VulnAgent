"""Cross-platform controlled execution semantics."""

from pathlib import Path
import sys

import pytest

from vulnagent.agents.fuzz_agent import FuzzAgent
from vulnagent.contracts import (
    AnalysisContext,
    EvidenceType,
    FuzzRequest,
    Target,
    TargetType,
    Task,
)
from vulnagent.execution.controlled_executor import ControlledExecutor, build_command
from vulnagent.fuzz.engine import ControlledFuzzEngine


def test_python_target_uses_current_interpreter(tmp_path: Path) -> None:
    target = tmp_path / "target.PY"

    command = build_command(target)

    assert command[0] == sys.executable
    assert command[1] == str(target)


def test_non_python_target_uses_native_command(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"

    assert build_command(target) == [str(target)]


def test_python_target_receives_stdin(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text(
        "import sys\ndata = sys.stdin.buffer.read()\nprint(len(data))\n",
        encoding="utf-8",
    )

    result = ControlledExecutor(timeout_seconds=2.0).execute(
        target=target,
        input_data=b"hello",
        work_dir=tmp_path,
    )

    assert result.executed is True
    assert result.returncode == 0
    assert result.crashed is False
    assert result.timed_out is False
    assert result.error is None
    assert b"5" in result.stdout


def test_nonzero_python_exit_is_a_crash(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text("raise SystemExit(7)\n", encoding="utf-8")

    result = ControlledExecutor(timeout_seconds=2.0).execute(
        target=target,
        input_data=b"",
        work_dir=tmp_path,
    )

    assert result.executed is True
    assert result.returncode == 7
    assert result.crashed is True
    assert result.timed_out is False
    assert result.error is None


@pytest.mark.asyncio
async def test_launch_failure_is_not_reported_as_a_crash(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"not an executable")
    request = FuzzRequest(
        task_id="launch-failure-task",
        target_id="launch-failure-target",
        target_path=str(target),
        authorized=True,
    )
    engine = ControlledFuzzEngine(mutation_count=1)

    result = await engine.run(request)

    assert result.executed is False
    assert result.metadata["attempts"] == 1
    assert result.metadata["executions"] == 0
    assert result.metadata["launch_failures"] == 1
    assert all(
        item.evidence_type is not EvidenceType.CRASH_LOG
        for item in result.evidence
    )
    runtime_evidence = next(
        item
        for item in result.evidence
        if item.evidence_type is EvidenceType.RUNTIME_TRACE
    )
    assert runtime_evidence.data["executed"] is False
    assert runtime_evidence.data["error"]

    task = Task(
        task_id="launch-failure-task",
        target=Target(
            target_id="launch-failure-target",
            path=str(target),
            target_type=TargetType.BINARY,
            metadata={"fuzz_authorized": True},
        ),
    )
    agent_result = await FuzzAgent(engine).run(
        task,
        AnalysisContext(task=task),
    )

    assert not any(
        finding.vulnerability_type == "fuzz_crash"
        for finding in agent_result.findings
    )
