from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from .backends import SandboxBackend, SubprocessBackend
from .policy import SandboxPolicy
from .result import SandboxResult


class SandboxManager:
    """
    Unified entry point for sandbox execution.

    The manager is responsible for:
    - validating the sandbox policy
    - selecting the execution backend
    - passing execution requests to the backend
    - returning a unified SandboxResult

    The manager itself does not execute processes.
    """

    def __init__(
        self,
        policy: Optional[SandboxPolicy] = None,
        backend: Optional[SandboxBackend] = None,
    ) -> None:
        self.policy = policy or SandboxPolicy()
        self.backend = backend or SubprocessBackend()

    def execute(
        self,
        command: List[str],
        work_dir: Optional[Path] = None,
    ) -> SandboxResult:
        """
        Execute a command through the configured sandbox backend.
        """

        self.policy.validate()

        if not command:
            return SandboxResult(
                executed=False,
                command=[],
                error="command must not be empty",
            )

        if work_dir is not None:
            work_dir = Path(work_dir).resolve()

            if not work_dir.exists():
                return SandboxResult(
                    executed=False,
                    command=list(command),
                    error="work_dir does not exist",
                )

            if not work_dir.is_dir():
                return SandboxResult(
                    executed=False,
                    command=list(command),
                    error="work_dir is not a directory",
                )

        return self.backend.execute(
            command=list(command),
            policy=self.policy,
        )