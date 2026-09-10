"""Static PE image headers and normal import/export directory parsing."""

from typing import Any

from vulnagent.contracts import ModuleExecutionError

from ._reader import ParsedBinary, ParseLimits, Reader, entropy


def parse_pe(data: bytes, limits: ParseLimits) -> ParsedBinary:
    """Parse PE32/PE32+ file-backed structures without loading the image."""
    reader = Reader(data, limits)
    pe_offset = reader.unpack("I", 0x3C)[0]
    reader.require(pe_offset, 24)
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ModuleExecutionError("Invalid PE signature")
    machine, section_count, _, _, _, optional_size, characteristics = reader.unpack(
        "HHIIIHH", pe_offset + 4
    )
    optional = pe_offset + 24
    reader.require(optional, optional_size)
    if optional_size < 2:
        raise ModuleExecutionError("Missing PE optional header")
    magic = reader.unpack("H", optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ModuleExecutionError(f"Unsupported PE optional header: {magic:#x}")
    bits = 32 if magic == 0x10B else 64
    directory_offset = 96 if bits == 32 else 112
    if optional_size < directory_offset:
        raise ModuleExecutionError("Truncated PE optional header")
    directory_count = reader.unpack("I", optional + directory_offset - 4)[0]
    if directory_count > (optional_size - directory_offset) // 8:
        raise ModuleExecutionError("PE directories exceed optional header")
    image_base = reader.unpack(
        "I" if bits == 32 else "Q", optional + (28 if bits == 32 else 24)
    )[0]
    header_size = reader.unpack("I", optional + 60)[0]
    reader.require(0, header_size)
    section_table = optional + optional_size
    reader.table(section_table, section_count, 40, 40, limits.max_sections)
    if header_size < section_table + section_count * 40:
        raise ModuleExecutionError(
            "PE SizeOfHeaders does not contain the section table"
        )
    entry_rva = reader.unpack("I", optional + 16)[0]
    result = ParsedBinary(
        "PE",
        {
            0x14C: "x86",
            0x8664: "x86_64",
            0x1C0: "arm",
            0x1C4: "arm",
            0xAA64: "aarch64",
        }.get(machine, f"unknown-{machine:#x}"),
        bits,
        "little",
        image_base + entry_rva if entry_rva else 0,
    )
    result.details = {
        "image_base": image_base,
        "entry_point_rva": entry_rva,
        "machine": machine,
        "characteristics": characteristics,
    }
    scanned_bytes = 0
    for index in range(section_count):
        row = section_table + index * 40
        name = data[row : row + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size, rva, raw_size, raw_offset = reader.unpack("IIII", row + 8)
        flags = reader.unpack("I", row + 36)[0]
        if raw_size:
            reader.require(raw_offset, raw_size)
        scanned_bytes += raw_size
        if scanned_bytes > len(data):
            raise ModuleExecutionError(
                "Overlapping PE section data exceeds analysis byte budget"
            )
        result.sections.append(
            {
                "name": name,
                "address": image_base + rva,
                "rva": rva,
                "virtual_size": virtual_size,
                "offset": raw_offset,
                "size": raw_size,
                "flags": flags,
                "entropy": entropy(data[raw_offset : raw_offset + raw_size]),
            }
        )

    def mapped(rva: int, size: int = 1) -> tuple[int, int]:
        if rva < header_size and size <= header_size - rva:
            reader.require(rva, size)
            return rva, header_size
        matches = [
            s
            for s in result.sections
            if 0 <= rva - s["rva"] < s["size"] and size <= s["size"] - (rva - s["rva"])
        ]
        if len(matches) != 1:
            raise ModuleExecutionError(f"PE RVA is unmapped or ambiguous: {rva:#x}")
        section = matches[0]
        offset = section["offset"] + rva - section["rva"]
        reader.require(offset, size)
        return offset, section["offset"] + section["size"]

    def name_at(rva: int) -> str:
        return reader.cstring(*mapped(rva))

    def directory(index: int) -> tuple[int, int]:
        if index >= directory_count:
            return 0, 0
        rva, size = reader.unpack("II", optional + directory_offset + index * 8)
        if bool(rva) != bool(size):
            raise ModuleExecutionError("Incomplete PE data directory")
        return rva, size

    import_rva, import_size = directory(1)
    if import_rva:
        start, _ = mapped(import_rva, import_size)
        descriptor_limit = min(import_size // 20, limits.max_symbols + 1)
        for index in range(descriptor_limit):
            lookup, stamp, chain, name_rva, iat = reader.unpack(
                "IIIII", start + index * 20
            )
            if not any((lookup, stamp, chain, name_rva, iat)):
                break
            if index >= limits.max_symbols:
                raise ModuleExecutionError("PE import descriptor limit exceeded")
            dll = name_at(name_rva)
            thunk = lookup or iat
            if not thunk:
                raise ModuleExecutionError("Missing PE import lookup table")
            step = bits // 8
            for ordinal_index in range(limits.max_symbols + 1):
                offset, _ = mapped(thunk + ordinal_index * step, step)
                value = reader.unpack("I" if bits == 32 else "Q", offset)[0]
                if not value:
                    break
                if len(result.imports) >= limits.max_symbols:
                    raise ModuleExecutionError("PE import symbol limit exceeded")
                if value & (1 << (bits - 1)):
                    symbol = f"#{value & 0xFFFF}"
                else:
                    mapped(value, 3)
                    symbol = name_at(value + 2)
                result.imports.append(f"{dll}!{symbol}")
            else:
                raise ModuleExecutionError("Unterminated PE import lookup table")
        else:
            raise ModuleExecutionError("Unterminated PE import descriptor table")

    export_rva, export_size = directory(0)
    if export_rva:
        if export_size < 40:
            raise ModuleExecutionError("Truncated PE export directory")
        start, _ = mapped(export_rva, export_size)
        _, _, _, _, _, ordinal_base, count, name_count, addresses, names, ordinals = (
            reader.unpack("IIHHIIIIIII", start)
        )
        if max(count, name_count) > limits.max_symbols:
            raise ModuleExecutionError("PE export symbol limit exceeded")
        address_start, _ = mapped(addresses, count * 4) if count else (0, 0)
        name_start, _ = mapped(names, name_count * 4) if name_count else (0, 0)
        ordinal_start, _ = mapped(ordinals, name_count * 2) if name_count else (0, 0)
        names_by_index: dict[int, list[str]] = {}
        for index in range(name_count):
            ordinal = reader.unpack("H", ordinal_start + index * 2)[0]
            if ordinal >= count:
                raise ModuleExecutionError("PE export ordinal outside address table")
            names_by_index.setdefault(ordinal, []).append(
                name_at(reader.unpack("I", name_start + index * 4)[0])
            )
        for index in range(count):
            rva = reader.unpack("I", address_start + index * 4)[0]
            if not rva:
                continue
            item: dict[str, Any] = {
                "names": names_by_index.get(index, []),
                "ordinal": ordinal_base + index,
                "rva": rva,
            }
            if export_rva <= rva < export_rva + export_size:
                offset, end = mapped(rva)
                item["forwarder"] = reader.cstring(
                    offset, min(end, start + export_size)
                )
            else:
                item["address"] = image_base + rva
            result.exports.append(item)
    for index, label in (
        (2, "resources"),
        (6, "debug/COFF symbols"),
        (13, "delay imports"),
    ):
        if directory(index)[0]:
            result.warnings.append(f"PE {label} are not decoded in T1")
    return result
