"""Bounded PE x64 call-site semantics for ambiguous UCRT wrappers.

The structural PE parser deliberately does not infer vulnerabilities from an
import name alone.  This optional Capstone-backed pass decodes executable
sections without executing the target and records the observable argument
shape at calls to selected runtime helpers.  It does not build a CFG or make a
final vulnerability decision.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._reader import ParsedBinary


_STDIO_HELPER = "__stdio_common_vsprintf"
_MAX_SECTION_BYTES = 8 * 1024 * 1024
_MAX_INSTRUCTIONS = 250_000
_LOOKBACK_INSTRUCTIONS = 20


def inspect_pe_x64_callsites(data: bytes, parsed: ParsedBinary) -> dict[str, Any]:
    """Return bounded call-site facts for ambiguous PE x64 UCRT helpers.

    Capstone belongs to the ``binary-analysis`` optional dependency group.  A
    missing decoder is represented as an explicit unavailable result so the
    dependency-free structural parser continues to work.
    """
    base = {
        "schema_version": 1,
        "analyzer": "pe-x64-callsite-semantics",
        "target_executed": False,
        "callsites": [],
        "limitations": [
            "local register-shape inference only",
            "no reachability or destination-buffer proof",
            "no final vulnerability verdict",
        ],
    }
    if parsed.file_format != "PE" or parsed.architecture != "x86_64" or parsed.bits != 64:
        return {**base, "available": False, "reason": "unsupported_format_or_architecture"}

    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
    except ImportError:
        return {**base, "available": False, "reason": "capstone_not_installed"}

    import_entries = parsed.details.get("import_entries", [])
    helper_iats = {
        int(entry["iat_address"])
        for entry in import_entries
        if isinstance(entry, Mapping)
        and str(entry.get("symbol", "")).casefold() == _STDIO_HELPER
        and isinstance(entry.get("iat_address"), int)
    }
    if not helper_iats:
        return {**base, "available": True, "helper_import": _STDIO_HELPER}

    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    # PE code sections may contain alignment bytes or embedded data between
    # functions. Continue after undecodable bytes while retaining hard caps.
    decoder.skipdata = True
    section_instructions: list[list[Any]] = []
    decoded_count = 0
    for section in parsed.sections:
        if not isinstance(section, Mapping):
            continue
        flags = section.get("flags")
        offset = section.get("offset")
        size = section.get("size")
        address = section.get("address")
        if not all(isinstance(value, int) for value in (flags, offset, size, address)):
            continue
        if not (flags & 0x20000000) or size <= 0 or size > _MAX_SECTION_BYTES:
            continue
        if offset < 0 or offset > len(data) - size:
            continue
        instructions = list(decoder.disasm(data[offset : offset + size], address))
        decoded_count += len(instructions)
        if decoded_count > _MAX_INSTRUCTIONS:
            return {**base, "available": False, "reason": "instruction_limit_exceeded"}
        section_instructions.append(instructions)

    thunk_addresses: set[int] = set()
    for instructions in section_instructions:
        for instruction in instructions:
            if instruction.mnemonic != "jmp" or len(instruction.operands) != 1:
                continue
            target = _rip_memory_target(instruction, instruction.operands[0], X86_OP_MEM, X86_REG_RIP)
            if target in helper_iats:
                thunk_addresses.add(instruction.address)

    callsites: list[dict[str, Any]] = []
    for instructions in section_instructions:
        for index, instruction in enumerate(instructions):
            if instruction.mnemonic != "call" or len(instruction.operands) != 1:
                continue
            operand = instruction.operands[0]
            target: int | None = None
            via = "unknown"
            if operand.type == X86_OP_IMM and int(operand.imm) in thunk_addresses:
                target = int(operand.imm)
                via = "import_thunk"
            elif _rip_memory_target(instruction, operand, X86_OP_MEM, X86_REG_RIP) in helper_iats:
                target = _rip_memory_target(instruction, operand, X86_OP_MEM, X86_REG_RIP)
                via = "direct_iat"
            if target is None:
                continue
            callsites.append(
                _describe_stdio_callsite(
                    instructions,
                    index,
                    target,
                    via,
                    X86_OP_IMM,
                    X86_OP_REG,
                )
            )

    return {
        **base,
        "available": True,
        "helper_import": _STDIO_HELPER,
        "helper_iat_addresses": sorted(helper_iats),
        "thunk_addresses": sorted(thunk_addresses),
        "decoded_instruction_count": decoded_count,
        "callsites": callsites,
    }


def _rip_memory_target(instruction: Any, operand: Any, mem_type: int, rip_register: int) -> int | None:
    if operand.type != mem_type or operand.mem.base != rip_register or operand.mem.index:
        return None
    return int(instruction.address + instruction.size + operand.mem.disp)


def _describe_stdio_callsite(
    instructions: list[Any],
    call_index: int,
    target: int,
    via: str,
    immediate_type: int,
    register_type: int,
) -> dict[str, Any]:
    start = max(0, call_index - _LOOKBACK_INSTRUCTIONS)
    window = instructions[start:call_index]
    # A preceding control-transfer normally marks the closest local argument
    # setup region.  Keep the window after it to avoid borrowing R8 writes from
    # an unrelated basic block.
    for boundary_index in range(len(window) - 1, -1, -1):
        if window[boundary_index].mnemonic in {"call", "jmp", "ret"}:
            window = window[boundary_index + 1 :]
            break

    argument: dict[str, Any] = {"register": "r8", "kind": "unknown"}
    for instruction in reversed(window):
        if not instruction.operands:
            continue
        destination = instruction.operands[0]
        if destination.type != register_type:
            continue
        register_name = instruction.reg_name(destination.reg).casefold()
        if register_name not in {"r8", "r8d", "r8w", "r8b"}:
            continue
        if instruction.mnemonic == "mov" and len(instruction.operands) >= 2:
            source = instruction.operands[1]
            if source.type == immediate_type:
                value = int(source.imm)
                argument = {
                    "register": "r8",
                    "kind": "constant",
                    "value": value,
                    "instruction_address": instruction.address,
                }
            else:
                argument = {
                    "register": "r8",
                    "kind": "dynamic",
                    "source": instruction.op_str,
                    "instruction_address": instruction.address,
                }
        else:
            argument = {
                "register": "r8",
                "kind": "computed",
                "source": instruction.op_str,
                "instruction_address": instruction.address,
            }
        break

    is_unbounded_sentinel = (
        argument.get("kind") == "constant"
        and int(argument.get("value", 0)) in {-1, 0xFFFFFFFFFFFFFFFF}
    )
    classification = "unbounded_format_write" if is_unbounded_sentinel else (
        "bounded_count_shape" if argument.get("kind") in {"constant", "dynamic"} else "unknown"
    )
    return {
        "address": instructions[call_index].address,
        "target_address": target,
        "via": via,
        "helper": _STDIO_HELPER,
        "third_argument": argument,
        "classification": classification,
        "inferred_api": "sprintf" if is_unbounded_sentinel else None,
        "confidence": 0.9 if is_unbounded_sentinel else 0.6,
        "instruction_window": [
            {
                "address": instruction.address,
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
            }
            for instruction in window[-8:]
        ],
    }
