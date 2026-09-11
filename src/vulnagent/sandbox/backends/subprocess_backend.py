from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from ..policy import SandboxPolicy
from ..result import SandboxResult
from .base import SandboxBackend


class SubprocessBackend(SandboxBackend):
    """
    Basic controlled subprocess execution backend.
    """

    def execute(
        self,
        command: List[str],
        policy: SandboxPolicy,
        work_dir: Optional[Path] = None,
        input_data: bytes = b"",
    ) -> SandboxResult:

        policy.validate()

        start_time = time.perf_counter()

        result = SandboxResult(
            command=list(command),
            metadata={
                "backend_name": "subprocess",
                "enforced_controls": [
                    "shell_disabled",
                    "wall_clock_timeout",
                    "stdio_capture",
                ],
                "unsupported_controls": [
                    "active_process_limit",
                    "cpu_time_limit",
                    "memory_limit",
                    "file_size_limit",
                    "filesystem_isolation",
                    "network_isolation",
                ],
                "network_isolation_enforced": False,
                "filesystem_isolation_enforced": False,
                "degraded": True,
            },
        )

        if not command:
            result.error = "command must not be empty"
            return result

        environment = os.environ.copy()

        if policy.environment:
            environment.update(policy.environment)

        timeout_seconds = policy.timeout_ms / 1000.0

        process = None

        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(work_dir) if work_dir else None,
                shell=False,
                text=False,
                env=environment,
                start_new_session=True,
            )

            result.executed = True

            try:
                stdout, stderr = process.communicate(
                    input=input_data,
                    timeout=timeout_seconds
                )

                result.stdout = stdout.decode(errors="replace")
                result.stderr = stderr.decode(errors="replace")
                result.return_code = process.returncode

            except subprocess.TimeoutExpired as exc:

                result.timed_out = True

                if exc.stdout:
                    result.stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout

                if exc.stderr:
                    result.stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr

                self._terminate_process(
                    process,
                    kill_tree=policy.kill_tree,
                )

                stdout, stderr = process.communicate()

                if stdout:
                    result.stdout += stdout.decode(errors="replace") if isinstance(stdout, bytes) else stdout

                if stderr:
                    result.stderr += stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr

                result.return_code = process.returncode

        except (OSError, ValueError) as exc:
            result.error = str(exc)

        finally:
            result.duration_ms = (
                time.perf_counter() - start_time
            ) * 1000.0

        result.crashed = self._is_crash(result)

        if policy.collect_runtime_trace:
            result.runtime_trace = (
                self._build_runtime_trace(result)
            )
            result.runtime_trace.append("sandbox_backend=subprocess")
            result.runtime_trace.append("network_isolation_enforced=false")
            result.runtime_trace.append("filesystem_isolation_enforced=false")

        return result

    def _terminate_process(
        self,
        process: subprocess.Popen,
        kill_tree: bool = True,
    ) -> None:
        """
        Terminate the target process.

        On Windows, taskkill can terminate the process tree.
        """

        if os.name == "nt" and kill_tree:

            try:
                subprocess.run(
                    [
                        "taskkill",
                        "/PID",
                        str(process.pid),
                        "/T",
                        "/F",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )

                return

            except OSError:
                pass

        try:
            process.terminate()

        except OSError:
            pass

    def _is_crash(
        self,
        result: SandboxResult,
    ) -> bool:
        """
        Determine whether the target appears to have crashed.
        """

        if not result.executed:
            return False

        if result.timed_out:
            return False

        if result.return_code is None:
            return False

        return result.return_code != 0

    def _build_runtime_trace(
        self,
        result: SandboxResult,
    ) -> List[str]:
        """
        Build a lightweight execution trace.
        """

        trace: List[str] = []

        if not result.executed:
            trace.append("process_launch_failed")
            trace.append(f"error={result.error}")
            trace.append(
                f"duration_ms={result.duration_ms:.2f}"
            )
            return trace

        trace.append("process_started")

        if result.timed_out:
            trace.append("timeout")

        elif result.crashed:
            trace.append("process_crashed")

        elif result.return_code == 0:
            trace.append("process_completed")

        else:
            trace.append("process_failed")

        trace.append(
            f"return_code={result.return_code}"
        )

        trace.append(
            f"duration_ms={result.duration_ms:.2f}"
        )

        return trace
