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
    ) -> SandboxResult:

        policy.validate()

        start_time = time.perf_counter()

        result = SandboxResult(
            command=list(command),
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
                text=True,
                env=environment,
                start_new_session=True,
            )

            result.executed = True

            try:
                stdout, stderr = process.communicate(
                    timeout=timeout_seconds
                )

                result.stdout = stdout
                result.stderr = stderr
                result.return_code = process.returncode

            except subprocess.TimeoutExpired as exc:

                result.timed_out = True

                if exc.stdout:
                    result.stdout = exc.stdout

                if exc.stderr:
                    result.stderr = exc.stderr

                self._terminate_process(
                    process,
                    kill_tree=policy.kill_tree,
                )

                stdout, stderr = process.communicate()

                if stdout:
                    result.stdout += stdout

                if stderr:
                    result.stderr += stderr

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