"""Bounded byte access shared by the PE and ELF readers."""

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from vulnagent.contracts import ModuleExecutionError


@dataclass(frozen=True)
class ParseLimits:
    """Resource limits for an individual static analysis request."""

    max_file_bytes: int = 32 * 1024 * 1024
    max_sections: int = 4096
    max_symbols: int = 10000
    max_symbol_name_bytes: int = 4096
    max_strings: int = 4096
    max_string_bytes: int = 1024
    min_string_chars: int = 4

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.min_string_chars > self.max_string_bytes:
            raise ValueError("min_string_chars must not exceed max_string_bytes")


@dataclass
class ParsedBinary:
    """Private parser state, converted to the existing public result at exit."""

    file_format: str
    architecture: str
    bits: int
    byte_order: str
    entry_point: int
    sections: list[dict[str, Any]] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[dict[str, Any]] = field(default_factory=list)
    functions: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class Reader:
    """Read only ranges that are fully contained in the input buffer."""

    def __init__(self, data: bytes, limits: ParseLimits, endian: str = "<") -> None:
        self.data = data
        self.limits = limits
        self.endian = endian

    def require(self, offset: int, size: int) -> None:
        """Reject truncated or invalid byte ranges before decoding."""
        if offset < 0 or size < 0 or offset > len(self.data) - size:
            raise ModuleExecutionError(
                f"Truncated or invalid binary range: offset={offset}, size={size}"
            )

    def unpack(self, layout: str, offset: int) -> tuple[Any, ...]:
        """Decode a bounded structure with the file's byte order."""
        layout = self.endian + layout
        self.require(offset, struct.calcsize(layout))
        return struct.unpack_from(layout, self.data, offset)

    def table(
        self, offset: int, count: int, stride: int, minimum: int, limit: int
    ) -> None:
        """Validate a table before any iteration over untrusted counts."""
        if count > limit:
            raise ModuleExecutionError(
                f"Binary table count {count} exceeds limit {limit}"
            )
        if stride < minimum:
            raise ModuleExecutionError(
                "Binary table entry is smaller than its format requires"
            )
        self.require(offset, count * stride)

    def cstring(self, offset: int, end: int) -> str:
        """Read a terminated symbol name within its owning table or section."""
        self.require(offset, 1)
        end = min(end, len(self.data), offset + self.limits.max_symbol_name_bytes + 1)
        stop = self.data.find(b"\0", offset, end)
        if stop < 0:
            raise ModuleExecutionError("Unterminated or oversized binary symbol name")
        return self.data[offset:stop].decode("utf-8", errors="replace")


def entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte; an empty range has zero entropy."""
    if not data:
        return 0.0
    size = len(data)
    return round(
        -sum((n / size) * math.log2(n / size) for n in Counter(data).values()), 6
    )
