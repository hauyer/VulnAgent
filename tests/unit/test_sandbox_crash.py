import sys

from vulnagent.sandbox import (
    SandboxManager,
    SandboxPolicy,
)


def test_nonzero_exit_is_reported_as_crash(tmp_path):
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
            "import sys; sys.exit(1)",
        ],
        work_dir=tmp_path,
    )

    assert result.executed is True
    assert result.return_code == 1
    assert result.crashed is True
    assert result.timed_out is False

    assert "process_crashed" in result.runtime_trace