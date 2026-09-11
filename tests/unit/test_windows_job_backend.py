"""Harmless Windows Job Object enforcement checks."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from vulnagent.sandbox import SandboxManager, SandboxPolicy, WindowsJobBackend


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows Job Object test")


def _native_python() -> str:
    candidate = Path(sys.base_prefix) / "python.exe"
    return str(candidate.resolve() if candidate.is_file() else Path(sys.executable).resolve())


def test_windows_job_records_enforced_and_unsupported_boundaries(tmp_path) -> None:
    policy = SandboxPolicy(
        timeout_ms=3000,
        max_processes=2,
        cpu_time_ms=1000,
        memory_limit_mb=128,
    )
    result = WindowsJobBackend().execute(
        [_native_python(), "-c", "print('job-ok')"],
        policy,
        work_dir=tmp_path,
    )

    assert result.success() is True
    assert "job-ok" in result.stdout
    assert result.metadata["backend_name"] == "windows_job"
    assert {
        "kill_on_job_close",
        "active_process_limit",
        "job_cpu_time_limit",
        "process_memory_limit",
        "job_memory_limit",
    }.issubset(result.metadata["enforced_controls"])
    assert result.metadata["network_isolation_enforced"] is False
    assert result.metadata["filesystem_isolation_enforced"] is False
    assert "sandbox_backend=windows_job" in result.runtime_trace


def test_windows_job_active_process_limit_blocks_child(tmp_path) -> None:
    code = (
        "import subprocess,sys\n"
        "try:\n"
        " subprocess.run([sys.executable, '-c', 'print(1)'], check=False)\n"
        "except OSError:\n"
        " print('child-blocked')\n"
        " raise SystemExit(0)\n"
        "raise SystemExit(9)\n"
    )
    result = WindowsJobBackend().execute(
        [_native_python(), "-c", code],
        SandboxPolicy(timeout_ms=3000, max_processes=1, memory_limit_mb=128),
        work_dir=tmp_path,
    )

    assert result.success() is True
    assert "child-blocked" in result.stdout


def test_windows_job_cpu_limit_terminates_busy_target_before_wall_timeout(tmp_path) -> None:
    result = WindowsJobBackend().execute(
        [_native_python(), "-c", "while True: pass"],
        SandboxPolicy(
            timeout_ms=5000,
            max_processes=1,
            cpu_time_ms=100,
            memory_limit_mb=128,
        ),
        work_dir=tmp_path,
    )

    assert result.executed is True
    assert result.timed_out is False
    assert result.return_code not in (None, 0)
    assert result.crashed is False
    assert result.metadata["resource_limit_hit"] == "cpu_time"
    assert result.duration_ms < 4000


def test_windows_job_memory_limit_prevents_large_allocation(tmp_path) -> None:
    code = (
        "try:\n"
        " value = bytearray(256 * 1024 * 1024)\n"
        " print('allocation-succeeded', len(value))\n"
        "except MemoryError:\n"
        " print('memory-limit-enforced')\n"
    )
    result = WindowsJobBackend().execute(
        [_native_python(), "-c", code],
        SandboxPolicy(
            timeout_ms=5000,
            max_processes=1,
            cpu_time_ms=2000,
            memory_limit_mb=64,
        ),
        work_dir=tmp_path,
    )

    assert result.executed is True
    assert "allocation-succeeded" not in result.stdout
    assert result.return_code != 0 or "memory-limit-enforced" in result.stdout


def test_manager_selects_windows_job_by_default() -> None:
    assert isinstance(SandboxManager().backend, WindowsJobBackend)
