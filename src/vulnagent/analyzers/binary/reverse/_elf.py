"""ELF section and symbol facts; no program loading or disassembly."""

from typing import Any

from vulnagent.contracts import ModuleExecutionError

from ._reader import ParsedBinary, ParseLimits, Reader, entropy


def parse_elf(data: bytes, limits: ParseLimits) -> ParsedBinary:
    """Decode ELF32/ELF64 headers, sections and section-backed symbol tables."""
    if len(data) < 16 or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        raise ModuleExecutionError("Invalid ELF identification header")
    bits = 32 if data[4] == 1 else 64
    byte_order = "little" if data[5] == 1 else "big"
    reader = Reader(data, limits, "<" if data[5] == 1 else ">")
    header = reader.unpack("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH", 16)
    (
        kind,
        machine,
        version,
        entry,
        phoff,
        shoff,
        flags,
        ehsize,
        phsize,
        phnum,
        shsize,
        shnum,
        shstr,
    ) = header
    if version != 1 or ehsize < (52 if bits == 32 else 64):
        raise ModuleExecutionError("Invalid ELF header version or size")
    reader.require(0, ehsize)
    layout = "IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ"
    section_size = 40 if bits == 32 else 64
    section_zero = None
    if shoff:
        reader.table(shoff, 1, shsize, section_size, limits.max_sections)
        section_zero = reader.unpack(layout, shoff)
        if section_zero[1] != 0:
            raise ModuleExecutionError("ELF section zero must be SHT_NULL")
        if shnum == 0:
            shnum = section_zero[5]
            if shnum == 0:
                raise ModuleExecutionError("Missing ELF extended section count")
        if shstr == 0xFFFF:
            shstr = section_zero[6]
        reader.table(shoff, shnum, shsize, section_size, limits.max_sections)
    elif shnum or shstr:
        raise ModuleExecutionError("ELF section count/index without a section table")
    if phnum == 0xFFFF:
        if section_zero is None:
            raise ModuleExecutionError("Missing ELF extended program header count")
        phnum = section_zero[7]
    if phnum:
        if not phoff:
            raise ModuleExecutionError("ELF program header count without a table")
        reader.table(
            phoff, phnum, phsize, 32 if bits == 32 else 56, limits.max_sections
        )
        for index in range(phnum):
            if bits == 32:
                segment_type, offset, _, _, file_size, memory_size, _, _ = (
                    reader.unpack("IIIIIIII", phoff + index * phsize)
                )
            else:
                segment_type, _, offset, _, _, file_size, memory_size, _ = (
                    reader.unpack("IIQQQQQQ", phoff + index * phsize)
                )
            if segment_type != 0 and file_size:
                reader.require(offset, file_size)
            if segment_type == 1 and file_size > memory_size:
                raise ModuleExecutionError(
                    "ELF load segment file size exceeds memory size"
                )
    result = ParsedBinary(
        "ELF",
        {
            3: "x86",
            8: "mips",
            20: "ppc",
            21: "ppc64",
            40: "arm",
            62: "x86_64",
            183: "aarch64",
            243: "riscv",
        }.get(machine, f"unknown-{machine:#x}"),
        bits,
        byte_order,
        entry,
    )
    result.details = {
        "machine": machine,
        "elf_type": kind,
        "flags": flags,
        "program_header_count": phnum,
        "address_kind": "section_relative" if kind == 1 else "virtual",
    }
    if not shoff:
        result.warnings.append(
            "ELF has no section table; dynamic symbols via PT_DYNAMIC are not decoded in T1"
        )
        return result
    sections = [reader.unpack(layout, shoff + i * shsize) for i in range(shnum)]
    if shstr >= shnum:
        raise ModuleExecutionError("ELF section-name table index outside section table")
    scanned_bytes = 0
    for index, row in enumerate(sections):
        (
            name,
            section_type,
            section_flags,
            address,
            offset,
            size,
            link,
            info,
            alignment,
            stride,
        ) = row
        file_size = 0 if section_type in (0, 8) else size
        if file_size:
            reader.require(offset, file_size)
        scanned_bytes += file_size
        if scanned_bytes > len(data):
            raise ModuleExecutionError(
                "Overlapping ELF section data exceeds analysis byte budget"
            )
        result.sections.append(
            {
                "index": index,
                "name": "",
                "type": section_type,
                "flags": section_flags,
                "address": address,
                "offset": offset,
                "size": file_size,
                "virtual_size": size,
                "entropy": entropy(data[offset : offset + file_size]),
            }
        )

    def string_at(table_index: int, offset: int) -> str:
        if (
            table_index <= 0
            or table_index >= len(sections)
            or sections[table_index][1] != 3
        ):
            raise ModuleExecutionError("ELF string-table reference is invalid")
        table = sections[table_index]
        if offset >= table[5]:
            raise ModuleExecutionError("ELF string offset outside its string table")
        return reader.cstring(table[4] + offset, table[4] + table[5])

    for index, row in enumerate(sections):
        if shstr:
            result.sections[index]["name"] = string_at(shstr, row[0])

    symbol_count = 0
    seen_functions: set[tuple[str, int, int]] = set()
    imports: dict[str, None] = {}
    for table_index, row in enumerate(sections):
        if row[1] not in (2, 11):
            continue
        offset, size, link, stride = row[4], row[5], row[6], row[9]
        minimum = 16 if bits == 32 else 24
        if stride < minimum or size % stride:
            raise ModuleExecutionError("Invalid ELF symbol table entry size")
        count = size // stride
        symbol_count += count
        reader.table(offset, count, stride, minimum, limits.max_symbols)
        if symbol_count > limits.max_symbols:
            raise ModuleExecutionError("ELF total symbol limit exceeded")
        for index in range(count):
            if bits == 32:
                name, value, length, info, other, section = reader.unpack(
                    "IIIBBH", offset + index * stride
                )
            else:
                name, info, other, section, value, length = reader.unpack(
                    "IBBHQQ", offset + index * stride
                )
            if section == 0xFFFF:
                raise ModuleExecutionError(
                    "ELF SHN_XINDEX symbols are not supported in T1"
                )
            if 0 < section < 0xFF00 and section >= shnum:
                raise ModuleExecutionError(
                    "ELF symbol section index outside section table"
                )
            symbol_name = string_at(link, name)
            if not symbol_name:
                continue
            binding, symbol_type = info >> 4, info & 0xF
            if row[1] == 11 and section == 0 and binding in (1, 2):
                imports[symbol_name] = None
            item: dict[str, Any] = {
                "name": symbol_name,
                "address": value,
                "size": length,
                "section_index": section,
                "source": "elf_dynsym" if row[1] == 11 else "elf_symtab",
                "table_index": table_index,
            }
            if (
                row[1] == 11
                and section != 0
                and binding in (1, 2)
                and (other & 3) in (0, 3)
            ):
                result.exports.append(dict(item))
            # Only symbol-table function declarations are facts; bytes are not decoded here.
            key = (symbol_name, value, section)
            if symbol_type == 2 and section != 0 and key not in seen_functions:
                result.functions.append(item)
                seen_functions.add(key)
    result.imports = list(imports)
    result.details["symbol_entries_scanned"] = symbol_count
    return result
