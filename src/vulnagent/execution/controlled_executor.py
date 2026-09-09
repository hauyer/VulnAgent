"""Controlled local target execution layer."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecutionResult:
    """Result of one target execution."""

    returncode: int | None
    timed_out: bool
    crashed: bool
    elapsed_ms: float
    stdout: bytes
    stderr: bytes
    signature: str


def build_command(target: Path) -> list[str]:
    """
    Build the command used to execute the target.

    On Windows, Python scripts are executed through
    the current Python interpreter.

    On Linux/macOS, executable files are executed directly.
    """

    if os.name == "nt":
        if target.suffix.lower() == ".py":
            return [
                sys.executable,
                str(target),
            ]

    return [str(target)]


class ControlledExecutor:
    """
    Execute an authorized local target with a timeout.

    The execution is intentionally isolated from the fuzz
    boundary. The fuzz layer only calls this interface.
    """

    def __init__(
        self,
        timeout_seconds: float = 1.0,
        max_output_bytes: int = 64 * 1024,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def execute(
        self,
        target: Path,
        input_data: bytes,
        work_dir: Path,
    ) -> ExecutionResult:
        """Execute target once with controlled input."""

        start = time.monotonic()

        process = None

        command = build_command(target)

        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(work_dir),
                shell=False,
            )

            stdout, stderr = process.communicate(
                input=input_data,
                timeout=self.timeout_seconds,
            )

            stdout = stdout[: self.max_output_bytes]
            stderr = stderr[: self.max_output_bytes]

            elapsed_ms = (
                time.monotonic() - start
            ) * 1000

            returncode = process.returncode

            crashed = (
                returncode is not None
                and returncode < 0
            )

            signature_data = (
                f"{returncode}|{crashed}|"
                f"{hashlib.sha256(stderr[:4096]).hexdigest()}"
            ).encode()

            signature = hashlib.sha256(
                signature_data
            ).hexdigest()[:16]

            return ExecutionResult(
                returncode=returncode,
                timed_out=False,
                crashed=crashed,
                elapsed_ms=elapsed_ms,
                stdout=stdout,
                stderr=stderr,
                signature=signature,
            )

        except subprocess.TimeoutExpired:
            if process is not None:
                process.kill()

                stdout, stderr = process.communicate()
            else:
                stdout = b""
                stderr = b""

            elapsed_ms = (
                time.monotonic() - start
            ) * 1000

            return ExecutionResult(
                returncode=None,
                timed_out=True,
                crashed=False,
                elapsed_ms=elapsed_ms,
                stdout=stdout[: self.max_output_bytes],
                stderr=stderr[: self.max_output_bytes],
                signature="timeout",
            )