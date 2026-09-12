"""Bounded DEX/APK structure inspection for local teaching samples."""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile
import zlib
from typing import Any

from vulnagent.contracts import ModuleExecutionError

from ._reader import ParseLimits, ParsedBinary, entropy


_DEX_MAGICS = (b"dex\n035\x00", b"dex\n037\x00", b"dex\n038\x00", b"dex\n039\x00", b"dex\n040\x00", b"dex\n041\x00")
_PROTECTOR_HINTS = {
    "bangcle": (b"libsecexe", b"secneo"),
    "ijiami": (b"ijiami", b"libexecmain"),
    "legu": (b"libshell", b"tencent_stub"),
    "dexguard": (b"dexguard", b"tamper detection"),
}


def is_dex(data: bytes) -> bool:
    return data.startswith(_DEX_MAGICS)


def is_apk(data: bytes) -> bool:
    return data.startswith(b"PK\x03\x04")


def repair_dex_header(data: bytes) -> bytes:
    """Recalculate the size, SHA-1 signature and Adler32 after memory capture."""

    if len(data) < 112 or not is_dex(data):
        raise ModuleExecutionError("Cannot repair an invalid or truncated DEX image")
    repaired = bytearray(data)
    struct.pack_into("<I", repaired, 32, len(repaired))
    repaired[12:32] = hashlib.sha1(repaired[32:]).digest()
    struct.pack_into("<I", repaired, 8, zlib.adler32(repaired[12:]) & 0xFFFFFFFF)
    return bytes(repaired)


def parse_dex_or_apk(data: bytes, limits: ParseLimits) -> ParsedBinary:
    """Parse DEX header facts or APK DEX inventory without executing code."""

    if is_dex(data):
        return _parse_dex(data, limits, container="DEX")
    if not is_apk(data):
        raise ModuleExecutionError("Expected a DEX or APK file")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            dex_names = sorted(name for name in names if name.startswith("classes") and name.endswith(".dex"))
            if not dex_names:
                raise ModuleExecutionError("APK contains no classes*.dex entry")
            if len(dex_names) > 128:
                raise ModuleExecutionError("APK DEX entry count exceeds limit")
            primary_info = archive.getinfo(dex_names[0])
            if primary_info.file_size > limits.max_file_bytes:
                raise ModuleExecutionError("APK primary DEX exceeds max_file_bytes")
            primary = archive.read(dex_names[0])
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        raise ModuleExecutionError(f"Invalid APK container: {exc}") from exc
    parsed = _parse_dex(primary, limits, container="APK")
    parsed.details.update({
        "dex_entries": dex_names,
        "dex_entry_count": len(dex_names),
        "apk_entry_count": len(names),
        "container_sha256": hashlib.sha256(data).hexdigest(),
    })
    parsed.sections.insert(0, {
        "name": "apk-container",
        "address": 0,
        "rva": 0,
        "virtual_size": len(data),
        "offset": 0,
        "size": len(data),
        "flags": 0,
        "entropy": entropy(data),
    })
    return parsed


def _parse_dex(data: bytes, limits: ParseLimits, *, container: str) -> ParsedBinary:
    if len(data) < 112 or not is_dex(data):
        raise ModuleExecutionError("Invalid or truncated DEX header")
    checksum = struct.unpack_from("<I", data, 8)[0]
    signature = data[12:32]
    file_size, header_size, endian_tag = struct.unpack_from("<III", data, 32)
    if file_size != len(data) or header_size < 112 or header_size > len(data):
        raise ModuleExecutionError("DEX header size or file size is inconsistent")
    fields = struct.unpack_from("<20I", data, 32)
    string_ids_size, string_ids_off = fields[6], fields[7]
    type_ids_size, method_ids_size, class_defs_size = fields[8], fields[14], fields[16]
    for count in (string_ids_size, type_ids_size, method_ids_size, class_defs_size):
        if count > limits.max_symbols:
            raise ModuleExecutionError("DEX table count exceeds symbol limit")
    strings = _dex_strings(data, string_ids_size, string_ids_off, limits)
    lowered = data.lower()
    protection_hints = [
        name for name, markers in _PROTECTOR_HINTS.items()
        if any(marker in lowered for marker in markers)
    ]
    parsed = ParsedBinary(container, "dalvik", 32, "little", 0)
    parsed.sections = [{
        "name": "classes.dex",
        "address": 0,
        "rva": 0,
        "virtual_size": len(data),
        "offset": 0,
        "size": len(data),
        "flags": 0,
        "entropy": entropy(data),
    }]
    parsed.details = {
        "dex_version": data[4:7].decode("ascii", errors="replace"),
        "checksum_valid": zlib.adler32(data[12:]) & 0xFFFFFFFF == checksum,
        "signature_valid": hashlib.sha1(data[32:]).digest() == signature,
        "endian_tag": endian_tag,
        "string_ids_size": string_ids_size,
        "type_ids_size": type_ids_size,
        "method_ids_size": method_ids_size,
        "class_defs_size": class_defs_size,
        "protection_hints": protection_hints,
        "dex_strings": strings,
        "dynamic_restore_strategy": "Frida ART DefineClass/OpenMemory capture in an authorized local emulator",
    }
    parsed.warnings.append("DEX method bodies are inventoried but not decompiled by the dependency-free parser")
    return parsed


def dex_strings(data: bytes, limits: ParseLimits) -> list[str]:
    """Public helper used by the static analyzer to avoid regex-only strings."""

    fields = struct.unpack_from("<20I", data, 32)
    return _dex_strings(data, fields[6], fields[7], limits)


def _dex_strings(data: bytes, count: int, offset: int, limits: ParseLimits) -> list[str]:
    if offset > len(data) or count * 4 > len(data) - offset:
        raise ModuleExecutionError("DEX string-id table is out of bounds")
    values: list[str] = []
    for index in range(count):
        item_offset = struct.unpack_from("<I", data, offset + index * 4)[0]
        if item_offset >= len(data):
            raise ModuleExecutionError("DEX string-data offset is out of bounds")
        cursor = item_offset
        for _ in range(5):
            byte = data[cursor]
            cursor += 1
            if byte & 0x80 == 0:
                break
            if cursor >= len(data):
                raise ModuleExecutionError("Truncated DEX string length")
        end = data.find(b"\0", cursor, min(len(data), cursor + limits.max_string_bytes + 1))
        if end < 0:
            continue
        values.append(data[cursor:end].decode("utf-8", errors="replace"))
    return list(dict.fromkeys(values))
