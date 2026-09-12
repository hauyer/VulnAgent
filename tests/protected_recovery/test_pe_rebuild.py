"""PE header and import reconstruction from an instructor-owned snapshot."""

from vulnagent.analyzers.binary.restoration import (
    ApiResolution,
    MemoryRegion,
    MemorySnapshot,
    PEImageRebuilder,
    ImportTableRebuilder,
)
from vulnagent.analyzers.binary.reverse._pe import parse_pe
from vulnagent.analyzers.binary.reverse._reader import ParseLimits


def test_rebuilds_parseable_pe_and_import_directory() -> None:
    snapshot = MemorySnapshot(
        image_base=0x400000,
        entry_point=0x401000,
        bits=32,
        machine=0x14C,
        regions=(
            MemoryRegion(0x401000, b"\x90\x90\xC3", executable=True, name=".text"),
            MemoryRegion(0x402000, b"VULNAGENT\0", writable=True, name=".data"),
        ),
        api_resolutions=(
            ApiResolution("KERNEL32.dll", "ExitProcess", 0x76001000),
            ApiResolution("USER32.dll", "MessageBoxA", 0x75001000),
        ),
        capture_evidence={"provider": "recorded-course-fixture"},
    )
    rebuilt = PEImageRebuilder().rebuild(snapshot)
    parsed = parse_pe(rebuilt.data, ParseLimits())
    assert rebuilt.section_count == 3
    assert rebuilt.import_count == 2
    assert parsed.entry_point == 0x401000
    assert parsed.imports == ["KERNEL32.dll!ExitProcess", "USER32.dll!MessageBoxA"]


def test_import_rebuilder_deduplicates_observed_loader_events() -> None:
    rebuilt = ImportTableRebuilder().rebuild(
        (
            ApiResolution("KERNEL32.dll", "ExitProcess"),
            ApiResolution("KERNEL32.dll", "ExitProcess"),
            ApiResolution("KERNEL32.dll", "CreateFileW"),
        ),
        section_rva=0x3000,
        bits=64,
    )
    assert rebuilt.dll_count == 1
    assert rebuilt.import_count == 2
    assert b"KERNEL32.dll\0" in rebuilt.data
