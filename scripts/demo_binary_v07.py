"""V0.7 Binary Intelligence closed-loop demo.

Builds a synthetic PE32+ image whose import table pulls in ``gets`` (external
input) and ``strcpy`` (dangerous sink), runs the structural parser
(``StaticBinaryReverseAnalyzer``), then the semantic IAT xref pass
(``BinaryXrefAnalyzer``) to locate the stripped binary chain

    external input -> function -> dangerous callsite

without relying on any function name, and emits the Binary Evidence Graph.

Usage:
    python -m scripts.demo_binary_v07
"""

from __future__ import annotations

import asyncio
import struct

from vulnagent.analyzers.binary.intel import BinaryXrefAnalyzer, build_binary_evidence_graph
from vulnagent.analyzers.binary.reverse import StaticBinaryReverseAnalyzer
from vulnagent.contracts import BinaryAnalysisRequest

IMAGE_BASE = 0x140000000
TASK_ID = "v07-binary-intel"
TARGET_ID = "synthetic-pe64-gets-strcpy"
SESSION_ID = "v07-demo"


def make_v07_pe() -> bytes:
    """PE32+ with two imports (gets, strcpy) and one strcpy callsite in .text."""
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x8664,  # PE32+
        2,
        0,
        0,
        0,
        240,
        0x22,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, IMAGE_BASE)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x3000, 0x200)
    directories = optional + 112
    struct.pack_into("<I", data, directories - 4, 16)
    # directory[0] export = 0 (none), directory[1] import = 0x2100.
    struct.pack_into("<IIII", data, directories, 0, 0, 0x2100, 0xA0)
    optional_size = 240
    table = optional + optional_size
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        table,
        b".text\0\0\0",
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        table + 40,
        b".rdata\0\0",
        0x400,
        0x2000,
        0x400,
        0x400,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    # Code: lea rcx,[rbp-0x20]; call [rip+gets]; mov rdx,rax;
    #       lea rcx,[rbp-0x20]; call [rip+strcpy]; ret
    code = bytearray(0x200)
    code[0:4] = b"\x48\x8d\x4d\xe0"
    gets_disp = 0x2260 - (0x1000 + 4 + 6)
    code[4:10] = b"\xff\x15" + struct.pack("<i", gets_disp)
    code[10:13] = b"\x48\x89\xc2"
    code[13:17] = b"\x48\x8d\x4d\xe0"
    strcpy_disp = 0x2268 - (0x1000 + 17 + 6)
    code[17:23] = b"\xff\x15" + struct.pack("<i", strcpy_disp)
    code[23] = 0xC3
    for index in range(24, 0x200):
        code[index] = 0x90
    data[0x200:0x400] = bytes(code)

    # Standard import directory inside .rdata (rva 0x2000, raw 0x400):
    # raw = 0x400 + (rva - 0x2000).
    struct.pack_into("<IIIII", data, 0x500, 0x2200, 0, 0, 0x22A0, 0x2200)  # KERNEL32
    struct.pack_into("<IIIII", data, 0x514, 0x2240, 0, 0, 0x22B0, 0x2260)  # msvcrt
    struct.pack_into("<IIIII", data, 0x528, 0, 0, 0, 0, 0)  # terminator
    data[0x6A0:0x6A0 + 13] = b"KERNEL32.dll\0"
    data[0x6B0:0x6B0 + 11] = b"msvcrt.dll\0"
    data[0x6C0:0x6C0 + 14] = b"\x00\x00ExitProcess\0"
    data[0x6D0:0x6D0 + 7] = b"\x00\x00gets\0"
    data[0x6D8:0x6D8 + 9] = b"\x00\x00strcpy\0"
    struct.pack_into("<QQ", data, 0x600, 0x22C0, 0)  # ExitProcess thunk/IAT
    struct.pack_into("<QQQ", data, 0x640, 0x22D0, 0x22D8, 0)  # gets+strcpy lookup
    struct.pack_into("<QQQ", data, 0x660, 0x22D0, 0x22D8, 0)  # gets+strcpy IAT
    return bytes(data)


async def main() -> None:
    print("=" * 72)
    print("VulnAgent V0.7 Binary Intelligence closed loop")
    print("target: synthetic PE32+ (gets -> strcpy), stripped (no function names)")
    print("=" * 72)

    fixture = make_v07_pe()
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory(prefix="v07_") as tmp:
        path = Path(tmp) / "sample.exe"
        path.write_bytes(fixture)
        analyzer = StaticBinaryReverseAnalyzer()
        parsed = await analyzer.analyze(
            BinaryAnalysisRequest(task_id=TASK_ID, target_id=TARGET_ID, path=str(path))
        )
        details = parsed.metadata.get("format_details", {})
        import_entries = details.get("import_entries", [])
        print("[parse] imports:")
        for entry in import_entries:
            print(f"  - {entry['dll']}!{entry['symbol']} iat={entry['iat_address']:x}")

        xref = BinaryXrefAnalyzer(
            data=fixture,
            sections=parsed.metadata.get("sections", []),
            import_entries=import_entries,
            image_base=IMAGE_BASE,
        )
        result = xref.analyze()
        print(f"\n[xref] available={result['available']}")
        print(f"[xref] dangerous imports: {result['dangerous_imports']}")
        print(f"[xref] input imports:     {result['input_imports']}")
        print(f"[xref] functions: {[(f['id'], hex(f['start_address']), hex(f['end_address'])) for f in result['functions']]}")
        print("[xref] callsites:")
        for callsite in result["callsites"]:
            print(
                f"  - {hex(callsite['address'])} role={callsite['role']} api={callsite['api']} "
                f"category={callsite['category']} in {callsite['function_id']}"
            )
        print("[xref] chains:")
        for chain in result["chains"]:
            print(
                f"  - {chain['kind']}: input({chain['input_api']}->{chain['input_source']}) "
                f"-> {chain['function_id']} -> {chain['dangerous_api']} "
                f"({chain['dangerous_category']}) @ {chain['callsite_address']:x}"
            )

        evidence, graph = build_binary_evidence_graph(
            result, task_id=TASK_ID, target_id=TARGET_ID, session_id=SESSION_ID, run_id="v07-run-1"
        )
        print(f"\n[graph] nodes={len(graph['nodes'])} edges={len(graph['edges'])}")
        for node in graph["nodes"]:
            print(f"  node[{node['id']}] kind={node['kind']} label={node['label']}")
        for edge in graph["edges"]:
            print(f"  edge {edge['source']} --{edge['label']}--> {edge['target']}")
        print(f"[evidence] records={len(evidence)}")
        for item in evidence:
            print(f"  - {item.evidence_id}: {item.description}")
    print("=" * 72)


if __name__ == "__main__":
    asyncio.run(main())
