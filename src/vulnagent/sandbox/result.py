from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SandboxResult:
    """
    Result returned by a sandbox execution.
    """

    executed: bool = False

    return_code: Optional[int] = None

    stdout: str = ""
    stderr: str = ""

    timed_out: bool = False
    crashed: bool = False

    duration_ms: float = 0.0

    command: List[str] = field(default_factory=list)

    error: Optional[str] = None

    runtime_trace: List[str] = field(default_factory=list)

    def success(self) -> bool:
        """
        Return True when the program executed normally
        and returned exit code 0.
        """
        return (
            self.executed
            and not self.timed_out
            and not self.crashed
            and self.return_code == 0
        )