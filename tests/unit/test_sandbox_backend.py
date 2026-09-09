import sys

from vulnagent.sandbox import (
    SandboxPolicy,
    SubprocessBackend,
)


def test_subprocess_backend_runs_python():
    policy = SandboxPolicy(
        timeout_ms=3000,
        collect_runtime_trace=True,
    )

    backend = SubprocessBackend()

    result = backend.execute(
        [
            sys.executable,
            "-c",
            "print('hello sandbox')",
        ],
        policy,
    )

    assert result.executed is True
    assert result.return_code == 0
    assert result.timed_out is False
    assert result.crashed is False

    assert "hello sandbox" in result.stdout

    assert "process_started" in result.runtime_trace
    assert "process_completed" in result.runtime_trace


def test_subprocess_backend_timeout():
    policy = SandboxPolicy(
        timeout_ms=200,
        collect_runtime_trace=True,
    )

    backend = SubprocessBackend()

    result = backend.execute(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(5)",
        ],
        policy,
    )

    assert result.executed is True
    assert result.timed_out is True

    assert "timeout" in result.runtime_trace


def test_subprocess_backend_nonzero_exit():
    policy = SandboxPolicy(
        timeout_ms=3000,
        collect_runtime_trace=True,
    )

    backend = SubprocessBackend()

    result = backend.execute(
        [
            sys.executable,
            "-c",
            "import sys; sys.exit(1)",
        ],
        policy,
    )

    assert result.executed is True
    assert result.return_code == 1
    assert result.crashed is True

    assert "process_crashed" in result.runtime_trace


def test_empty_command_is_rejected():
    policy = SandboxPolicy()

    backend = SubprocessBackend()

    result = backend.execute(
        [],
        policy,
    )

    assert result.executed is False
    assert result.error is not None