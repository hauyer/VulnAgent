"""Synthetic, non-executable fixtures for the P4 binary boundary."""

import hashlib
import random
import struct
from pathlib import Path

import pytest

from vulnagent.analyzers.binary.reverse import (
    MockBinaryReverseAnalyzer,
    ParseLimits,
    StaticBinaryReverseAnalyzer,
)
from vulnagent.contracts import (
    BinaryAnalysisRequest,
    BinaryAnalysisResult,
    ModuleExecutionError,
)


def make_pe(bits: int = 64) -> bytes:
    """Build a minimal PE image with named/ordinal imports and forwarded exports."""
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if bits == 64 else 224
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x8664 if bits == 64 else 0x14C,
        2,
        0,
        0,
        0,
        optional_size,
        0x22,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B if bits == 64 else 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into(
        "<Q" if bits == 64 else "<I",
        data,
        optional + (24 if bits == 64 else 28),
        0x140000000 if bits == 64 else 0x400000,
    )
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x3000, 0x200)
    directories = optional + (112 if bits == 64 else 96)
    struct.pack_into("<I", data, directories - 4, 16)
    struct.pack_into("<IIII", data, directories, 0x2100, 0xA0, 0x2000, 40)
    table = optional + optional_size
    for index, (name, rva, size, offset, flags) in enumerate(
        (
            (b".text", 0x1000, 0x200, 0x200, 0x60000020),
            (b".rdata", 0x2000, 0x400, 0x400, 0x40000040),
        )
    ):
        struct.pack_into(
            "<8sIIIIIIHHI",
            data,
            table + index * 40,
            name,
            size,
            rva,
            size,
            offset,
            0,
            0,
            0,
            0,
            flags,
        )
    data[0x200:0x206] = b"hello\0"
    data[0x220:0x22C] = "world\0".encode("utf-16-le")
    struct.pack_into("<IIIII", data, 0x400, 0x2060, 0, 0, 0x2080, 0x2060)
    struct.pack_into(
        "<QQQ" if bits == 64 else "<III", data, 0x460, 0x20A0, (1 << (bits - 1)) | 7, 0
    )
    data[0x480:0x48D] = b"KERNEL32.dll\0"
    data[0x4A2:0x4AE] = b"ExitProcess\0"
    struct.pack_into(
        "<IIHHIIIIIII", data, 0x500, 0, 0, 0, 0, 0x2080, 1, 2, 1, 0x2140, 0x2150, 0x2160
    )
    struct.pack_into("<II", data, 0x540, 0x1000, 0x2190)
    struct.pack_into("<I", data, 0x550, 0x2170)
    struct.pack_into("<H", data, 0x560, 0)
    data[0x570:0x577] = b"export\0"
    data[0x590:0x59C] = b"OTHER.Sleep\0"
    return bytes(data)


def make_pe_stdio_call(*, unbounded: bool) -> bytes:
    """Build a PE32+ fixture that calls the shared UCRT formatting helper."""
    data = bytearray(make_pe())
    data[0x200:0x400] = b"\x90" * 0x200
    helper = b"__stdio_common_vsprintf\0"
    data[0x4A2 : 0x4A2 + len(helper)] = helper
    image_base = 0x140000000
    stub_rva = 0x1100
    stub_offset = 0x300
    helper_iat_rva = 0x2060
    displacement = helper_iat_rva - (stub_rva + 6)
    data[stub_offset : stub_offset + 6] = b"\xff\x25" + struct.pack("<i", displacement)

    wrapper_rva = 0x1120
    wrapper_offset = 0x320
    setup = b"\x49\xc7\xc0\xff\xff\xff\xff" if unbounded else b"\x49\x89\xf0"
    call_rva = wrapper_rva + len(setup)
    relative = stub_rva - (call_rva + 5)
    data[wrapper_offset : wrapper_offset + len(setup) + 6] = (
        setup + b"\xe8" + struct.pack("<i", relative) + b"\xc3"
    )
    assert image_base + helper_iat_rva > image_base + call_rva
    return bytes(data)


def make_elf(bits: int = 64, endian: str = "<") -> bytes:
    """Build a minimal ELF with dynamic imports, object exports and functions."""
    data = bytearray(0x500)
    data[:7] = b"\x7fELF" + bytes(
        (2 if bits == 64 else 1, 1 if endian == "<" else 2, 1)
    )
    struct.pack_into(
        endian + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"),
        data,
        16,
        3,
        62 if bits == 64 else 3,
        1,
        0x401000,
        0,
        0x300,
        0,
        64 if bits == 64 else 52,
        0,
        0,
        64 if bits == 64 else 40,
        6,
        4,
    )
    strings = b"\0puts\0verify\0global\0hidden\0"
    names = b"\0.text\0.dynstr\0.dynsym\0.shstrtab\0.bss\0"
    data[0x80:0x86] = b"hello\0"
    data[0xA0 : 0xA0 + len(strings)] = strings
    data[0x200 : 0x200 + len(names)] = names
    stride = 24 if bits == 64 else 16
    for i, (name, value, length, info, other, section) in enumerate(
        (
            (0, 0, 0, 0, 0, 0),
            (1, 0, 0, 0x12, 0, 0),
            (6, 0x401000, 8, 0x12, 0, 1),
            (13, 0x402000, 4, 0x11, 0, 5),
            (20, 0x401008, 8, 0x12, 2, 1),
        )
    ):
        values = (
            (name, info, other, section, value, length)
            if bits == 64
            else (name, value, length, info, other, section)
        )
        struct.pack_into(
            endian + ("IBBHQQ" if bits == 64 else "IIIBBH"),
            data,
            0xE0 + i * stride,
            *values,
        )
    rows = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, 0x401000, 0x80, 16, 0, 0, 16, 0),
        (7, 3, 2, 0, 0xA0, len(strings), 0, 0, 1, 0),
        (15, 11, 2, 0, 0xE0, 5 * stride, 2, 1, 8, stride),
        (23, 3, 0, 0, 0x200, len(names), 0, 0, 1, 0),
        (33, 8, 3, 0x402000, 0xFFFF, 4096, 0, 0, 8, 0),
    )
    for index, row in enumerate(rows):
        struct.pack_into(
            endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"),
            data,
            0x300 + index * (64 if bits == 64 else 40),
            *row,
        )
    return bytes(data)


async def analyze(
    tmp_path: Path, data: bytes, limits: ParseLimits | None = None
) -> BinaryAnalysisResult:
    path = tmp_path / "sample.data"
    path.write_bytes(data)
    return await StaticBinaryReverseAnalyzer(limits).analyze(
        BinaryAnalysisRequest(task_id="task-p4", target_id="target-p4", path=str(path))
    )


@pytest.mark.parametrize("bits", [32, 64])
async def test_pe_facts_and_contract_round_trip(tmp_path: Path, bits: int) -> None:
    data = make_pe(bits)
    result = await analyze(tmp_path, data)
    assert result.file_format == "PE"
    assert result.architecture == ("x86_64" if bits == 64 else "x86")
    assert result.imports == ["KERNEL32.dll!ExitProcess", "KERNEL32.dll!#7"]
    assert {"hello", "world"} <= set(result.strings)
    assert result.metadata["sha256"] == hashlib.sha256(data).hexdigest()
    assert result.metadata["entry_point"] == (0x140001000 if bits == 64 else 0x401000)
    assert [s["name"] for s in result.metadata["sections"]] == [".text", ".rdata"]
    assert result.metadata["exports"][0]["names"] == ["export"]
    assert result.metadata["exports"][1]["forwarder"] == "OTHER.Sleep"
    assert result.functions == [] and result.cfg == {}
    assert result.metadata["packing_signals"]["inspector"] == "bounded-packing-signals"
    assert result.metadata["executed"] is False and result.metadata["mock"] is False
    assert BinaryAnalysisResult.model_validate_json(result.model_dump_json()) == result
    assert Path(result.path).read_bytes() == data


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("endian", ["<", ">"])
async def test_elf_endianness_symbols_and_nobits(
    tmp_path: Path, bits: int, endian: str
) -> None:
    result = await analyze(tmp_path, make_elf(bits, endian))
    assert result.file_format == "ELF"
    assert result.architecture == ("x86_64" if bits == 64 else "x86")
    assert result.metadata["bits"] == bits
    assert result.metadata["byte_order"] == ("little" if endian == "<" else "big")
    assert result.imports == ["puts"]
    assert [f["name"] for f in result.functions] == ["verify", "hidden"]
    assert [f["name"] for f in result.metadata["exports"]] == ["verify", "global"]
    assert result.functions[0]["address"] == 0x401000
    bss = result.metadata["sections"][5]
    assert bss["name"] == ".bss" and bss["size"] == 0 and bss["virtual_size"] == 4096
    assert result.cfg == {}
    assert result.metadata["executed"] is False
    assert BinaryAnalysisResult.model_validate_json(result.model_dump_json()) == result


async def test_elf_extended_section_counts(tmp_path: Path) -> None:
    data = bytearray(make_elf())
    struct.pack_into("<HH", data, 60, 0, 0xFFFF)
    struct.pack_into("<QI", data, 0x300 + 32, 6, 4)
    result = await analyze(tmp_path, bytes(data))
    assert len(result.metadata["sections"]) == 6
    assert result.imports == ["puts"]


async def test_sectionless_elf_is_explicit_about_missing_symbols(
    tmp_path: Path,
) -> None:
    data = bytearray(make_elf())
    struct.pack_into("<Q", data, 40, 0)
    struct.pack_into("<HH", data, 60, 0, 0)
    result = await analyze(tmp_path, bytes(data))
    assert result.imports == [] and result.functions == []
    assert "no section table" in result.metadata["warnings"][0]


@pytest.mark.parametrize(
    "data", [b"", b"text", b"MZ", b"\x7fELF", make_pe()[:0x400], make_elf()[:0x400]]
)
async def test_unsupported_and_truncated_inputs_raise_contract_error(
    tmp_path: Path, data: bytes
) -> None:
    with pytest.raises(ModuleExecutionError):
        await analyze(tmp_path, data)


@pytest.mark.parametrize(
    "kind",
    [
        "pe_section",
        "pe_rva",
        "pe_ordinal",
        "elf_string",
        "elf_stride",
        "elf_symbol_section",
        "elf_string_table",
    ],
)
async def test_malformed_references_are_rejected(tmp_path: Path, kind: str) -> None:
    data = bytearray(make_pe() if kind.startswith("pe") else make_elf())
    if kind == "pe_section":
        struct.pack_into("<I", data, 0x188 + 20, 0xFFFFFF00)
    elif kind == "pe_rva":
        struct.pack_into("<I", data, 0x400, 0xFFFFFF00)
    elif kind == "pe_ordinal":
        struct.pack_into("<H", data, 0x560, 2)
    elif kind == "elf_string":
        struct.pack_into("<I", data, 0xE0 + 24, 0xFFFFFF00)
    elif kind == "elf_stride":
        struct.pack_into("<Q", data, 0x300 + 3 * 64 + 56, 0)
    elif kind == "elf_symbol_section":
        struct.pack_into("<H", data, 0xE0 + 2 * 24 + 6, 100)
    else:
        struct.pack_into("<I", data, 0x300 + 3 * 64 + 40, 1)
    with pytest.raises(ModuleExecutionError):
        await analyze(tmp_path, bytes(data))


@pytest.mark.parametrize(
    "limits",
    [
        ParseLimits(max_file_bytes=100),
        ParseLimits(max_sections=1),
        ParseLimits(max_symbols=1),
    ],
)
@pytest.mark.parametrize("data", [make_pe(), make_elf()])
async def test_resource_limits_fail_explicitly(
    tmp_path: Path, limits: ParseLimits, data: bytes
) -> None:
    with pytest.raises(ModuleExecutionError):
        await analyze(tmp_path, data, limits)


async def test_string_limits_report_truncation(tmp_path: Path) -> None:
    result = await analyze(
        tmp_path, make_pe(), ParseLimits(max_strings=2, max_string_bytes=4)
    )
    assert len(result.metadata["string_locations"]) <= 2
    assert all(len(value) <= 4 for value in result.strings)
    assert result.metadata["strings_truncated"] is True
    assert result.metadata["warnings"]


@pytest.mark.parametrize("is_directory", [True, False])
async def test_non_file_inputs(tmp_path: Path, is_directory: bool) -> None:
    path = tmp_path if is_directory else tmp_path / "absent.exe"
    with pytest.raises(ModuleExecutionError):
        await StaticBinaryReverseAnalyzer().analyze(
            BinaryAnalysisRequest(task_id="t", target_id="x", path=str(path))
        )


async def test_mock_remains_non_reading() -> None:
    result = await MockBinaryReverseAnalyzer().analyze(
        BinaryAnalysisRequest(task_id="t", target_id="x", path="does-not-exist.exe")
    )
    assert result.metadata == {"mock": True, "executed": False}


async def test_pe_import_address_table_fallback(tmp_path: Path) -> None:
    data = bytearray(make_pe())
    struct.pack_into("<I", data, 0x400, 0)
    result = await analyze(tmp_path, bytes(data))
    assert result.imports == ["KERNEL32.dll!ExitProcess", "KERNEL32.dll!#7"]


@pytest.mark.parametrize(
    ("unbounded", "classification", "inferred_api"),
    [
        (True, "unbounded_format_write", "sprintf"),
        (False, "bounded_count_shape", None),
    ],
)
async def test_pe_x64_stdio_callsite_semantics_are_argument_sensitive(
    tmp_path: Path,
    unbounded: bool,
    classification: str,
    inferred_api: str | None,
) -> None:
    pytest.importorskip("capstone")
    result = await analyze(tmp_path, make_pe_stdio_call(unbounded=unbounded))

    semantics = result.metadata["callsite_semantics"]
    assert semantics["available"] is True
    assert semantics["target_executed"] is False
    assert len(semantics["callsites"]) == 1
    callsite = semantics["callsites"][0]
    assert callsite["classification"] == classification
    assert callsite["inferred_api"] == inferred_api
    assert callsite["instruction_window"]
    assert result.cfg == {}


async def test_pe_rejects_unterminated_import_descriptors(tmp_path: Path) -> None:
    data = bytearray(make_pe())
    struct.pack_into("<I", data, 0x98 + 112 + 12, 20)
    with pytest.raises(ModuleExecutionError, match="Unterminated"):
        await analyze(tmp_path, bytes(data))


async def test_elf_relocatable_function_addresses_are_section_relative(
    tmp_path: Path,
) -> None:
    data = bytearray(make_elf())
    struct.pack_into("<H", data, 16, 1)
    struct.pack_into("<Q", data, 0xE0 + 2 * 24 + 8, 4)
    result = await analyze(tmp_path, bytes(data))
    assert result.functions[0]["address"] == 4
    assert result.metadata["format_details"]["address_kind"] == "section_relative"


async def test_elf_truncated_load_segment(tmp_path: Path) -> None:
    data = bytearray(make_elf())
    struct.pack_into("<Q", data, 32, 0x250)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 0x250, 1, 5, len(data) - 1, 0, 0, 4096, 4096, 1)
    with pytest.raises(ModuleExecutionError, match="range"):
        await analyze(tmp_path, bytes(data))


async def test_symbol_name_limit_is_separate_from_display_strings(
    tmp_path: Path,
) -> None:
    with pytest.raises(ModuleExecutionError, match="symbol name"):
        await analyze(tmp_path, make_pe(), ParseLimits(max_symbol_name_bytes=4))


@pytest.mark.parametrize("data", [make_pe(), make_elf()])
async def test_seeded_header_mutations_never_leak_parser_exceptions(
    tmp_path: Path, data: bytes
) -> None:
    rng = random.Random(4)
    for _ in range(40):
        changed = bytearray(data)
        offset = rng.randrange(len(changed) - 4)
        changed[offset : offset + 4] = rng.randbytes(4)
        try:
            result = await analyze(tmp_path, bytes(changed))
        except ModuleExecutionError:
            continue
        assert result.metadata["executed"] is False
        assert (
            BinaryAnalysisResult.model_validate_json(result.model_dump_json()) == result
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_file_bytes": 0},
        {"max_strings": -1},
        {"max_sections": True},
        {"max_string_bytes": 2},
    ],
)
def test_invalid_limit_configuration(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        ParseLimits(**kwargs)
