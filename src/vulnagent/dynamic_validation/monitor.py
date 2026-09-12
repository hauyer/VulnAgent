"""Read-only process-state monitor adapters for robustness validation."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol

from .models import ProcessSnapshot


class ProcessHandle(Protocol):
    """Minimal process surface; the monitor never starts or controls a process."""

    @property
    def returncode(self) -> int | None: ...


class ProcessHandleMonitor:
    """Observe liveness plus optional sandbox-provided memory diagnostics."""

    def __init__(
        self,
        process: ProcessHandle,
        *,
        memory_reader: Callable[[], Awaitable[int | None]] | None = None,
        memory_error_reader: Callable[[], Awaitable[bool]] | None = None,
    ) -> None:
        self.process = process
        self.memory_reader = memory_reader
        self.memory_error_reader = memory_error_reader

    async def snapshot(self) -> ProcessSnapshot:
        memory_bytes = await self.memory_reader() if self.memory_reader else None
        memory_error = await self.memory_error_reader() if self.memory_error_reader else False
        return ProcessSnapshot(
            running=self.process.returncode is None,
            exit_code=self.process.returncode,
            memory_bytes=memory_bytes,
            memory_error_detected=memory_error,
        )


__all__ = ["ProcessHandle", "ProcessHandleMonitor"]
