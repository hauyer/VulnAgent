"""Import Address Table reconstruction from observed loader resolutions."""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass

from vulnagent.contracts import ModuleExecutionError

from .models import ApiResolution


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass(frozen=True, slots=True)
class RebuiltImportTable:
    """A file-independent PE import-directory payload."""

    data: bytes
    import_count: int
    dll_count: int


class ImportTableRebuilder:
    """Build standard descriptors, ILTs, IATs and hint/name entries.

    Input must come from an authorized isolated trace of loader/API resolution
    events.  Resolved process addresses are intentionally not copied because
    ASLR makes them unsuitable for a portable restored image.
    """

    def __init__(self, *, max_imports: int = 10_000, max_name_bytes: int = 255) -> None:
        self.max_imports = max_imports
        self.max_name_bytes = max_name_bytes

    def rebuild(
        self,
        resolutions: tuple[ApiResolution, ...],
        *,
        section_rva: int,
        bits: int,
    ) -> RebuiltImportTable:
        if bits not in {32, 64}:
            raise ModuleExecutionError("Import rebuilding supports only PE32 or PE32+")
        if section_rva <= 0:
            raise ModuleExecutionError("Import section RVA must be positive")

        grouped: dict[str, list[str]] = defaultdict(list)
        for item in resolutions[: self.max_imports]:
            dll = item.dll.strip()
            symbol = item.symbol.strip()
            if dll and symbol and symbol not in grouped[dll]:
                grouped[dll].append(symbol)
        if not grouped:
            return RebuiltImportTable(b"", 0, 0)

        step = bits // 8
        dlls = sorted(grouped, key=str.casefold)
        descriptor_size = (len(dlls) + 1) * 20
        blob = bytearray(descriptor_size)
        layouts: list[tuple[int, int, int, list[int]]] = []
        cursor = descriptor_size
        for dll in dlls:
            cursor = _align(cursor, step)
            ilt = cursor
            cursor += (len(grouped[dll]) + 1) * step
            iat = cursor
            cursor += (len(grouped[dll]) + 1) * step
            dll_name = cursor
            encoded_dll = dll.encode("ascii", errors="replace")[: self.max_name_bytes] + b"\0"
            blob.extend(b"\0" * (cursor + len(encoded_dll) - len(blob)))
            blob[dll_name:dll_name + len(encoded_dll)] = encoded_dll
            cursor += len(encoded_dll)
            name_offsets: list[int] = []
            for symbol in grouped[dll]:
                cursor = _align(cursor, 2)
                name_offset = cursor
                encoded = b"\0\0" + symbol.encode("ascii", errors="replace")[: self.max_name_bytes] + b"\0"
                blob.extend(b"\0" * (cursor + len(encoded) - len(blob)))
                blob[name_offset:name_offset + len(encoded)] = encoded
                cursor += len(encoded)
                name_offsets.append(name_offset)
            layouts.append((ilt, iat, dll_name, name_offsets))

        blob.extend(b"\0" * (cursor - len(blob)))
        pointer_format = "<I" if bits == 32 else "<Q"
        for index, (ilt, iat, dll_name, name_offsets) in enumerate(layouts):
            struct.pack_into(
                "<IIIII",
                blob,
                index * 20,
                section_rva + ilt,
                0,
                0,
                section_rva + dll_name,
                section_rva + iat,
            )
            for symbol_index, name_offset in enumerate(name_offsets):
                value = section_rva + name_offset
                struct.pack_into(pointer_format, blob, ilt + symbol_index * step, value)
                struct.pack_into(pointer_format, blob, iat + symbol_index * step, value)

        return RebuiltImportTable(
            data=bytes(blob),
            import_count=sum(len(values) for values in grouped.values()),
            dll_count=len(dlls),
        )
