"""V0.7 Binary Intelligence: IAT xref analyzer unit tests.

Synthetic PE32+ style sections and import entries (the structural parser's
``import_entries`` contract) with hand-assembled x64 instruction bytes — no
executable target is ever run.
"""

from __future__ import annotations

import struct

from vulnagent.analyzers.binary.intel import (
    BinaryXrefAnalyzer,
    build_binary_evidence_graph,
)

IMAGE_BASE = 0x140000000
TEXT_START = 0x140001000
GETS_IAT = 0x140002060
STRCPY_IAT = 0x140002068


def _rel_call(address: int, iat_address: int) -> bytes:
    displacement = iat_address - (address + 6)
    return b"\xff\x15" + struct.pack("<i", displacement)


def make_code_sections() -> bytes:
    """F1: input(gets) + dangerous(strcpy) in one function.
    F2: input(gets) then calls F1 -> inter-function chain."""
    code = bytearray()
    lea = b"\x48\x8d\x4d\xe0"  # lea rcx, [rbp-0x20]
    mov = b"\x48\x89\xc2"  # mov rdx, rax
    ret = b"\xc3"

    f1_start = TEXT_START
    code += lea  # 0x1000
    code += _rel_call(TEXT_START + 4, GETS_IAT)  # 0x1004
    code += mov  # 0x100A
    code += lea  # 0x100D
    code += _rel_call(TEXT_START + 0x11, STRCPY_IAT)  # 0x1011
    code += ret  # 0x1017

    f2_start = TEXT_START + 0x18
    assert len(code) == f2_start - TEXT_START
    code += lea  # 0x1018
    code += _rel_call(TEXT_START + 0x1C, GETS_IAT)  # 0x101C
    call_f1 = f1_start - (TEXT_START + 0x22 + 5)
    code += b"\xe8" + struct.pack("<i", call_f1)  # 0x1022 call F1
    code += ret  # 0x1027
    return bytes(code)


def make_import_entries() -> list[dict]:
    return [
        {"dll": "msvcrt.dll", "symbol": "gets", "iat_address": GETS_IAT},
        {"dll": "msvcrt.dll", "symbol": "strcpy", "iat_address": STRCPY_IAT},
        {"dll": "KERNEL32.dll", "symbol": "ExitProcess", "iat_address": 0x140002070},
    ]


def make_analyzer() -> BinaryXrefAnalyzer:
    code = make_code_sections()
    data = b"\x90" * 0x200 + code + b"\x00" * (0x100 - len(code))
    sections = [
        {
            "name": ".text",
            "offset": 0x200,
            "size": 0x100,
            "address": TEXT_START,
            "flags": 0x60000020,
        }
    ]
    return BinaryXrefAnalyzer(
        data=data, sections=sections, import_entries=make_import_entries(), image_base=IMAGE_BASE
    )


def test_intra_function_chain() -> None:
    result = make_analyzer().analyze()
    assert result["available"] is True
    callsites = result["callsites"]
    assert len(callsites) == 3  # gets x2 (F1, F2), strcpy x1
    assert any(c["api"] == "gets" and c["role"] == "input" for c in callsites)
    assert any(c["api"] == "strcpy" and c["role"] == "dangerous" for c in callsites)
    # ExitProcess is not in the dangerous/input catalogs.
    assert all(c["api"] != "ExitProcess" for c in callsites)
    chains = result["chains"]
    intra = [c for c in chains if c["kind"] == "intra_function"]
    assert len(intra) == 1
    assert intra[0]["input_api"] == ["gets"]
    assert intra[0]["dangerous_api"] == "strcpy"
    assert intra[0]["function_id"] == "f_140001000"


def test_inter_function_chain_via_call_edge() -> None:
    result = make_analyzer().analyze()
    assert len(result["call_edges"]) == 1
    edge = result["call_edges"][0]
    assert edge["caller_function"] == "f_140001018"
    assert edge["callee_function"] == "f_140001000"
    inter = [c for c in result["chains"] if c["kind"] == "inter_function"]
    assert len(inter) == 1
    assert inter[0]["input_api"] == ["gets"]
    assert inter[0]["dangerous_api"] == "strcpy"
    assert inter[0]["function_id"] == "f_140001000"


def test_stripped_function_boundaries_are_address_based() -> None:
    result = make_analyzer().analyze()
    ids = [f["id"] for f in result["functions"]]
    assert ids == ["f_140001000", "f_140001018"]
    # No symbol name anywhere in the function identity.
    assert all("strcpy" not in f["id"] and "gets" not in f["id"] for f in result["functions"])


def test_binary_evidence_graph_shape() -> None:
    result = make_analyzer().analyze()
    evidence, graph = build_binary_evidence_graph(
        result, task_id="t", target_id="pe-x64", session_id="s", run_id="r"
    )
    assert len(evidence) == len(result["chains"])
    kinds = {e.evidence_type for e in evidence}
    assert kinds == {"disassembly"}
    assert graph["engine"] == "binary-xref"
    # input -> function and function -> callsite edges per chain.
    assert len(graph["edges"]) == 2 * len(result["chains"])
    labels = {e["label"] for e in graph["edges"]}
    assert labels == {"inputs_to", "reaches"}


def test_import_thunk_via_jmp_is_detected() -> None:
    """A `jmp [rip+iat]` import thunk plus a `call thunk` reaches the sink."""
    code = bytearray()
    lea = b"\x48\x8d\x4d\xe0"
    f1_start = TEXT_START
    code += lea  # 0x1000
    code += _rel_call(TEXT_START + 4, STRCPY_IAT)  # direct iat call
    code += b"\xc3"  # ret 0x100A
    data = b"\x90" * 0x200 + bytes(code) + b"\x00" * (0x100 - len(code))
    sections = [
        {
            "name": ".text",
            "offset": 0x200,
            "size": 0x100,
            "address": TEXT_START,
            "flags": 0x60000020,
        }
    ]
    result = BinaryXrefAnalyzer(
        data=data, sections=sections, import_entries=make_import_entries(), image_base=IMAGE_BASE
    ).analyze()
    assert result["available"] is True
    assert any(c["api"] == "strcpy" and c["via"] == "direct_iat" for c in result["callsites"])
