"""Controlled local target execution layer."""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from vulnagent.sandbox import SandboxManager, SandboxPolicy


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
    runtime_trace: list[str]


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
    Controlled execution adapter used by the fuzz layer.

    The actual process execution is delegated to SandboxManager.
    """

    def __init__(
        self,
        timeout_seconds: float = 1.0,
        max_output_bytes: int = 64 * 1024,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

        self.sandbox = SandboxManager(
            policy=SandboxPolicy(
                timeout_ms=int(
                    timeout_seconds * 1000
                ),
                collect_runtime_trace=True,
            )
        )

    def execute(
        self,
        target: Path,
        input_data: bytes,
        work_dir: Path,
    ) -> ExecutionResult:
        """
        Execute target once through the sandbox.
        """

        # 根据目标文件构造执行命令
        command = build_command(target)

        # 交给 SandboxManager 执行
        sandbox_result = self.sandbox.execute(
            command=command,
            work_dir=work_dir,
        )

        # SandboxResult 中的 stdout/stderr 为字符串。
        # 转换成 bytes，保持原 Fuzz Engine 接口不变。
        stdout = sandbox_result.stdout.encode(
            errors="replace"
        )

        stderr = sandbox_result.stderr.encode(
            errors="replace"
        )

        # 限制输出大小
        stdout = stdout[: self.max_output_bytes]
        stderr = stderr[: self.max_output_bytes]

        # 获取目标程序返回码
        returncode = sandbox_result.return_code

        # 保持原来的 Fuzz Engine Crash 判断逻辑：
        # 只有负返回码才认为是信号级 Crash。
        crashed = (
            returncode is not None
            and returncode < 0
            and not sandbox_result.timed_out
        )

        # Timeout 使用固定 signature
        if sandbox_result.timed_out:
            signature = "timeout"

        else:
            # 使用返回码、Crash 状态和 stderr 哈希
            # 构造本次执行的 execution signature。
            signature_data = (
                f"{returncode}|{crashed}|"
                f"{hashlib.sha256(stderr[:4096]).hexdigest()}"
            ).encode()

            signature = hashlib.sha256(
                signature_data
            ).hexdigest()[:16]

        # 将 SandboxResult 转换为 ExecutionResult。
        #
        # runtime_trace 从 Sandbox 层继续向上传递，
        # 后续由 Fuzz Engine 写入 Evidence。
        return ExecutionResult(
            returncode=returncode,
            timed_out=sandbox_result.timed_out,
            crashed=crashed,
            elapsed_ms=sandbox_result.duration_ms,
            stdout=stdout,
            stderr=stderr,
            signature=signature,
            runtime_trace=list(
                sandbox_result.runtime_trace
            ),
        )