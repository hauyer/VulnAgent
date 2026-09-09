import sys

from vulnagent.sandbox import (
    SandboxManager,
    SandboxPolicy,
)


def test_sandbox_manager_runs_target(tmp_path):
    policy = SandboxPolicy(
        timeout_ms=3000,
        collect_runtime_trace=True,
    )

    manager = SandboxManager(
        policy=policy
    )

    result = manager.execute(
        command=[
            sys.executable,
            "-c",
            "print('sandbox manager ok')",
        ],
        work_dir=tmp_path,
    )

    assert result.executed is True
    assert result.return_code == 0
    assert result.timed_out is False

    assert "sandbox manager ok" in result.stdout

    assert "process_started" in result.runtime_trace
    assert "process_completed" in result.runtime_trace


def test_sandbox_manager_timeout(tmp_path):
    policy = SandboxPolicy(
        timeout_ms=200,
        collect_runtime_trace=True,
    )

    manager = SandboxManager(
        policy=policy
    )

    result = manager.execute(
        command=[
            sys.executable,
            "-c",
            "import time; time.sleep(5)",
        ],
        work_dir=tmp_path,
    )

    assert result.executed is True
    assert result.timed_out is True

    assert "timeout" in result.runtime_trace


def test_sandbox_manager_rejects_invalid_work_dir(tmp_path):
    policy = SandboxPolicy()

    manager = SandboxManager(
        policy=policy
    )

    missing_dir = tmp_path / "does_not_exist"

    result = manager.execute(
        command=[
            sys.executable,
            "-c",
            "print('test')",
        ],
        work_dir=missing_dir,
    )

    assert result.executed is False
    assert result.error == "work_dir does not exist"