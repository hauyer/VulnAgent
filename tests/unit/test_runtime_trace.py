import sys

from vulnagent.sandbox import (
    SandboxManager,
    SandboxPolicy,
)


def test_runtime_trace_for_normal_execution(tmp_path):
    manager = SandboxManager(
        policy=SandboxPolicy(
            timeout_ms=3000,
            collect_runtime_trace=True,
        )
    )

    result = manager.execute(
        command=[
            sys.executable,
            "-c",
            "print('normal execution')",
        ],
        work_dir=tmp_path,
    )

    assert result.executed is True
    assert result.timed_out is False
    assert result.crashed is False

    assert "process_started" in result.runtime_trace
    assert "process_completed" in result.runtime_trace

    assert any(
        item.startswith("return_code=")
        for item in result.runtime_trace
    )

    assert any(
        item.startswith("duration_ms=")
        for item in result.runtime_trace
    )


def test_runtime_trace_for_timeout(tmp_path):
    manager = SandboxManager(
        policy=SandboxPolicy(
            timeout_ms=200,
            collect_runtime_trace=True,
        )
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

    assert "process_started" in result.runtime_trace
    assert "timeout" in result.runtime_trace


def test_runtime_trace_can_be_disabled(tmp_path):
    manager = SandboxManager(
        policy=SandboxPolicy(
            timeout_ms=3000,
            collect_runtime_trace=False,
        )
    )

    result = manager.execute(
        command=[
            sys.executable,
            "-c",
            "print('trace disabled')",
        ],
        work_dir=tmp_path,
    )

    assert result.executed is True
    assert result.runtime_trace == []