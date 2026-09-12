"""Ports for Windows Debug API and Frida-based isolated capture helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .models import MemorySnapshot


class WindowsDebugSnapshotProvider(Protocol):
    """Sandbox helper port implemented with CreateProcess/WaitForDebugEvent.

    A concrete provider must run outside the web/API process, apply a job object
    and network policy, detect the OEP transition, record loader resolutions,
    and return copied regions.  Keeping that boundary injectable prevents an
    uploaded sample from being executed on the application host.
    """

    async def capture(
        self,
        path: str | Path,
        *,
        authorized: bool,
        timeout_seconds: float,
    ) -> MemorySnapshot: ...


class FridaDexSnapshotProvider(Protocol):
    """Local-emulator port for ART DEX captures.

    Implementations hook ART class definition/open-memory boundaries in an
    explicitly selected emulator and return checksum-validated DEX files.
    """

    async def capture_dex(
        self,
        apk_path: str | Path,
        *,
        authorized: bool,
        emulator_serial: str,
        timeout_seconds: float,
    ) -> tuple[bytes, ...]: ...


class RecordedSnapshotProvider:
    """Deterministic provider for tests and instructor-recorded lab captures."""

    def __init__(self, snapshot: MemorySnapshot) -> None:
        self.snapshot = snapshot

    async def capture(self, path: str | Path, *, authorized: bool, timeout_seconds: float) -> MemorySnapshot:
        if not authorized:
            raise PermissionError("dynamic capture requires explicit authorization")
        return self.snapshot
