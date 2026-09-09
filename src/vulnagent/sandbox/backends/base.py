from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from ..policy import SandboxPolicy
from ..result import SandboxResult


class SandboxBackend(ABC):
    """
    Abstract interface for sandbox execution backends.
    """

    @abstractmethod
    def execute(
        self,
        command: List[str],
        policy: SandboxPolicy,
        work_dir: Optional[Path] = None,
    ) -> SandboxResult:
        """
        Execute a command according to the sandbox policy.
        """
        raise NotImplementedError