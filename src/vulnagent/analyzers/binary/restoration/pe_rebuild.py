"""Deterministic PE image and import-directory reconstruction.

This module operates only on bytes captured by an injected, isolated debugger
provider.  It does not attach to or start processes itself.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from vulnagent.contracts import ModuleExecutionError

from ..reverse._pe import parse_pe
from ..reverse._reader import ParseLimits
from .imports import ImportTableRebuilder
from .models import MemoryRegion, MemorySnapshot


_FILE_ALIGNMENT = 0x200
_SECTION_ALIGNMENT = 0x1000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass(frozen=True, slots=True)
class RebuiltImage:
    data: bytes
    section_count: int
    import_count: int
    entry_point_rva: int


class PEImageRebuilder:
    """Rebuild a conventional PE32/PE32+ file from mapped image regions."""

    def __init__(self, *, max_regions: int = 96, max_image_bytes: int = 64 * 1024 * 1024) -> None:
        self.max_regions = max_regions
        self.max_image_bytes = max_image_bytes
        self.import_rebuilder = ImportTableRebuilder()

    def rebuild(self, snapshot: MemorySnapshot) -> RebuiltImage:
        """Create a parser-valid image and a standard import directory."""

        if snapshot.bits not in {32, 64}:
            raise ModuleExecutionError("PE rebuild supports only 32-bit or 64-bit snapshots")
        regions = self._regions(snapshot)
        section_rows: list[dict[str, object]] = []
        for index, region in enumerate(regions):
            rva = region.base_address - snapshot.image_base
            if rva < 0:
                raise ModuleExecutionError("Snapshot region precedes image base")
            section_rows.append({
                "name": self._section_name(region, index),
                "rva": _align(rva, _SECTION_ALIGNMENT),
                "data": region.data,
                "flags": self._characteristics(region),
            })

        next_rva = _align(
            max(int(item["rva"]) + len(item["data"]) for item in section_rows),
            _SECTION_ALIGNMENT,
        )
        rebuilt_imports = self.import_rebuilder.rebuild(
            snapshot.api_resolutions,
            section_rva=next_rva,
            bits=snapshot.bits,
        )
        import_blob, import_count = rebuilt_imports.data, rebuilt_imports.import_count
        if import_blob:
            section_rows.append({
                "name": ".idata",
                "rva": next_rva,
                "data": import_blob,
                "flags": 0xC0000040,
            })

        optional_size = 0xE0 if snapshot.bits == 32 else 0xF0
        pe_offset = 0x80
        section_table = pe_offset + 24 + optional_size
        size_of_headers = _align(section_table + len(section_rows) * 40, _FILE_ALIGNMENT)
        raw_cursor = size_of_headers
        for item in section_rows:
            item["raw_offset"] = raw_cursor
            item["raw_size"] = _align(len(item["data"]), _FILE_ALIGNMENT)
            raw_cursor += int(item["raw_size"])
        if raw_cursor > self.max_image_bytes:
            raise ModuleExecutionError("Rebuilt PE exceeds configured image limit")

        output = bytearray(raw_cursor)
        output[:2] = b"MZ"
        struct.pack_into("<I", output, 0x3C, pe_offset)
        output[0x40:0x80] = b"VulnAgent authorized teaching reconstruction\0".ljust(0x40, b"\0")
        output[pe_offset:pe_offset + 4] = b"PE\0\0"
        struct.pack_into(
            "<HHIIIHH",
            output,
            pe_offset + 4,
            snapshot.machine,
            len(section_rows),
            0,
            0,
            0,
            optional_size,
            0x0022 if snapshot.bits == 64 else 0x0102,
        )
        optional = pe_offset + 24
        self._optional_header(
            output,
            optional,
            snapshot,
            section_rows,
            size_of_headers,
            import_rva=(next_rva if import_blob else 0),
            import_size=(len(import_blob) if import_blob else 0),
        )
        for index, item in enumerate(section_rows):
            row = section_table + index * 40
            output[row:row + 8] = str(item["name"]).encode("ascii", errors="replace")[:8].ljust(8, b"\0")
            data = bytes(item["data"])
            struct.pack_into(
                "<IIIIIIHHI",
                output,
                row + 8,
                len(data),
                int(item["rva"]),
                int(item["raw_size"]),
                int(item["raw_offset"]),
                0,
                0,
                0,
                0,
                int(item["flags"]),
            )
            start = int(item["raw_offset"])
            output[start:start + len(data)] = data

        # The project's strict parser is also the acceptance gate for rebuilt bytes.
        parse_pe(bytes(output), ParseLimits(max_file_bytes=self.max_image_bytes))
        entry_rva = snapshot.entry_point - snapshot.image_base
        return RebuiltImage(bytes(output), len(section_rows), import_count, entry_rva)

    def _regions(self, snapshot: MemorySnapshot) -> list[MemoryRegion]:
        regions = [item for item in snapshot.regions if item.data]
        if not regions or len(regions) > self.max_regions:
            raise ModuleExecutionError("Snapshot must contain a bounded non-empty image region set")
        ordered = sorted(regions, key=lambda item: item.base_address)
        previous_end = -1
        total = 0
        for item in ordered:
            if item.base_address < previous_end:
                raise ModuleExecutionError("Snapshot image regions overlap")
            previous_end = item.base_address + len(item.data)
            total += len(item.data)
        if total > self.max_image_bytes:
            raise ModuleExecutionError("Snapshot image bytes exceed configured limit")
        return ordered

    @staticmethod
    def _section_name(region: MemoryRegion, index: int) -> str:
        if region.name:
            name = region.name if region.name.startswith(".") else f".{region.name}"
            return name[:8]
        if region.executable:
            return ".text" if index == 0 else f".tx{index}"
        if region.writable:
            return ".data" if index == 1 else f".dt{index}"
        return f".r{index}"

    @staticmethod
    def _characteristics(region: MemoryRegion) -> int:
        flags = 0x00000020 if region.executable else 0x00000040
        if region.readable:
            flags |= 0x40000000
        if region.writable:
            flags |= 0x80000000
        if region.executable:
            flags |= 0x20000000
        return flags

    @staticmethod
    def _optional_header(
        output: bytearray,
        offset: int,
        snapshot: MemorySnapshot,
        sections: list[dict[str, object]],
        size_of_headers: int,
        *,
        import_rva: int,
        import_size: int,
    ) -> None:
        bits = snapshot.bits
        magic = 0x10B if bits == 32 else 0x20B
        struct.pack_into("<H", output, offset, magic)
        entry_rva = snapshot.entry_point - snapshot.image_base
        if entry_rva < 0:
            raise ModuleExecutionError("Snapshot entry point precedes image base")
        struct.pack_into("<I", output, offset + 16, entry_rva)
        code_sections = [item for item in sections if int(item["flags"]) & 0x20000000]
        base_code = int(code_sections[0]["rva"]) if code_sections else int(sections[0]["rva"])
        struct.pack_into("<I", output, offset + 20, base_code)
        if bits == 32:
            data_sections = [item for item in sections if int(item["flags"]) & 0x80000000]
            struct.pack_into("<I", output, offset + 24, int(data_sections[0]["rva"]) if data_sections else base_code)
            struct.pack_into("<I", output, offset + 28, snapshot.image_base)
        else:
            struct.pack_into("<Q", output, offset + 24, snapshot.image_base)
        struct.pack_into("<II", output, offset + 32, _SECTION_ALIGNMENT, _FILE_ALIGNMENT)
        struct.pack_into("<HHHHHH", output, offset + 40, 6, 0, 0, 0, 6, 0)
        size_of_image = _align(
            max(int(item["rva"]) + len(item["data"]) for item in sections),
            _SECTION_ALIGNMENT,
        )
        struct.pack_into("<II", output, offset + 56, size_of_image, size_of_headers)
        struct.pack_into("<H", output, offset + 68, 3)  # Windows console subsystem
        number_of_rva_offset = offset + (92 if bits == 32 else 108)
        struct.pack_into("<I", output, number_of_rva_offset, 16)
        directory = offset + (96 if bits == 32 else 112)
        if import_rva:
            struct.pack_into("<II", output, directory + 8, import_rva, import_size)
