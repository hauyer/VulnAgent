"""Internal DTOs for sandbox-captured program images."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class MemoryRegion:
    """One committed image region copied by an isolated debugger helper."""

    base_address: int
    data: bytes
    readable: bool = True
    writable: bool = False
    executable: bool = False
    name: str | None = None


@dataclass(frozen=True, slots=True)
class ApiResolution:
    """One observed loader resolution used to reconstruct PE imports."""

    dll: str
    symbol: str
    resolved_address: int | None = None


@dataclass(frozen=True, slots=True)
class MemorySnapshot:
    """Serializable boundary returned by a Windows-debugger sandbox helper."""

    image_base: int
    entry_point: int
    bits: int
    machine: int
    regions: tuple[MemoryRegion, ...]
    api_resolutions: tuple[ApiResolution, ...] = ()
    capture_evidence: dict[str, object] = field(default_factory=dict)
