"""V0.7 Binary Intelligence: IAT xref analysis for PE x64 images.

``BinaryXrefAnalyzer`` walks the executable sections of a PE32+ image with
Capstone (without executing the target) and:

1. locates call/jmp sites that reach dangerous runtime APIs via the import
   address table (IAT xrefs),
2. locates call sites that reach external-input APIs (gets/fgets/scanf/...),
3. infers function boundaries in a stripped image from ``ret`` terminator
   boundaries (address-based function identities, no symbol names required),
4. builds the ``external input -> function -> dangerous callsite`` chains that
   the V0.7 acceptance criteria require, both intra-function (input and
   dangerous API in the same inferred function) and inter-function (input
   function calls a dangerous function).

The analyzer consumes the structural ``import_entries`` contract produced by
``reverse/_pe.py`` (``dll`` / ``symbol`` / ``iat_address``) so the dependency
free structural parser and this semantic pass stay decoupled.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any

from .catalog import DANGEROUS_APIS, INPUT_APIS, dangerous_category, input_source_kind

logger = logging.getLogger(__name__)

_MAX_SECTION_BYTES = 8 * 1024 * 1024
_MAX_INSTRUCTIONS = 250_000
_SCHEMA_VERSION = 1


class BinaryXrefAnalyzer:
    """Bounded PE x64 dangerous/input callsite analysis via IAT xrefs."""

    def __init__(
        self,
        *,
        data: bytes,
        sections: Sequence[Mapping[str, Any]],
        import_entries: Sequence[Mapping[str, Any]],
        image_base: int,
    ) -> None:
        self.data = data
        self.sections = sections
        self.import_entries = import_entries
        self.image_base = image_base

    # -- public -------------------------------------------------------------

    def analyze(self) -> dict[str, Any]:
        base: dict[str, Any] = {
            "schema_version": _SCHEMA_VERSION,
            "analyzer": "pe-x64-iat-xref",
            "target_executed": False,
            "available": False,
            "functions": [],
            "callsites": [],
            "call_edges": [],
            "chains": [],
            "limitations": [
                "local instruction-window analysis only",
                "function boundaries inferred from ret terminators (stripped heuristic)",
                "no reachability or destination-buffer proof",
                "no final vulnerability verdict",
            ],
        }
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
            from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
        except ImportError:
            return {**base, "reason": "capstone_not_installed"}

        dangerous_by_iat: dict[int, tuple[str, str]] = {}
        input_by_iat: dict[int, tuple[str, str]] = {}
        for entry in self.import_entries:
            if not isinstance(entry, Mapping):
                continue
            symbol = str(entry.get("symbol", ""))
            iat = entry.get("iat_address")
            if not isinstance(iat, int):
                continue
            category = dangerous_category(symbol)
            if category:
                dangerous_by_iat[iat] = (symbol, category)
            source = input_source_kind(symbol)
            if source:
                input_by_iat[iat] = (symbol, source)

        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        decoder.skipdata = True
        instructions: list[Any] = []
        decoded_count = 0
        for section in self.sections:
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
            if offset < 0 or offset > len(self.data) - size:
                continue
            chunk = list(decoder.disasm(self.data[offset : offset + size], address))
            decoded_count += len(chunk)
            if decoded_count > _MAX_INSTRUCTIONS:
                return {**base, "reason": "instruction_limit_exceeded"}
            instructions.extend(chunk)

        # IAT thunks: `jmp [rip+disp]` targeting a known IAT slot.
        thunk_by_address: dict[int, tuple[str, str]] = {}
        for instruction in instructions:
            if instruction.mnemonic != "jmp" or len(instruction.operands) != 1:
                continue
            target = _rip_memory_target(instruction, instruction.operands[0], X86_OP_MEM, X86_REG_RIP)
            if target in dangerous_by_iat:
                thunk_by_address[instruction.address] = ("dangerous", dangerous_by_iat[target])
            elif target in input_by_iat:
                thunk_by_address[instruction.address] = ("input", input_by_iat[target])

        # Function boundaries from ret terminators (stripped heuristic).
        # Only ret-closed regions count as functions; an unclosed trailing
        # region (alignment/data padding after the last ret) is discarded so
        # zero-filled section tails do not fabricate functions.
        functions: list[dict[str, Any]] = []
        current_start: int | None = None
        current_count = 0
        for instruction in instructions:
            if current_start is None:
                current_start = instruction.address
                current_count = 0
            current_count += 1
            if instruction.mnemonic == "ret":
                functions.append(
                    {
                        "id": _func_id(current_start),
                        "start_address": current_start,
                        "end_address": instruction.address,
                        "instruction_count": current_count,
                    }
                )
                current_start = None
                current_count = 0

        def function_of(address: int) -> dict[str, Any] | None:
            for function in functions:
                if function["start_address"] <= address <= function["end_address"]:
                    return function
            return None

        # Callsites + intra-code call edges.
        callsites: list[dict[str, Any]] = []
        call_edges: list[dict[str, Any]] = []
        for instruction in instructions:
            if instruction.mnemonic not in {"call", "jmp"} or len(instruction.operands) != 1:
                continue
            operand = instruction.operands[0]
            target = _rip_memory_target(instruction, operand, X86_OP_MEM, X86_REG_RIP)
            if target is not None and target in dangerous_by_iat:
                symbol, category = dangerous_by_iat[target]
                function = function_of(instruction.address)
                callsites.append(
                    {
                        "address": instruction.address,
                        "api": symbol,
                        "category": category,
                        "role": "dangerous",
                        "via": "direct_iat",
                        "function_id": function["id"] if function else None,
                    }
                )
                continue
            if target is not None and target in input_by_iat:
                symbol, source = input_by_iat[target]
                function = function_of(instruction.address)
                callsites.append(
                    {
                        "address": instruction.address,
                        "api": symbol,
                        "category": source,
                        "role": "input",
                        "via": "direct_iat",
                        "function_id": function["id"] if function else None,
                    }
                )
                continue
            if instruction.mnemonic == "call" and operand.type == X86_OP_IMM:
                callee = function_of(int(operand.imm))
                caller = function_of(instruction.address)
                if callee is not None and caller is not None and callee["id"] != caller["id"]:
                    call_edges.append(
                        {
                            "caller_function": caller["id"],
                            "call_address": instruction.address,
                            "callee_address": int(operand.imm),
                            "callee_function": callee["id"],
                        }
                    )

        # Chains: external input -> function -> dangerous callsite.
        chains: list[dict[str, Any]] = []
        for function in functions:
            dangerous = [c for c in callsites if c["role"] == "dangerous" and c["function_id"] == function["id"]]
            inputs = [c for c in callsites if c["role"] == "input" and c["function_id"] == function["id"]]
            if dangerous and inputs:
                chains.append(
                    {
                        "input_api": sorted({c["api"] for c in inputs}),
                        "input_source": inputs[0]["category"],
                        "function_id": function["id"],
                        "function_start": function["start_address"],
                        "dangerous_api": dangerous[0]["api"],
                        "dangerous_category": dangerous[0]["category"],
                        "callsite_address": dangerous[0]["address"],
                        "kind": "intra_function",
                    }
                )
        caller_has_input: dict[str, bool] = {
            c["function_id"]: True for c in callsites if c["role"] == "input" and c["function_id"]
        }
        callee_has_dangerous: dict[str, bool] = {
            c["function_id"]: True for c in callsites if c["role"] == "dangerous" and c["function_id"]
        }
        for edge in call_edges:
            if caller_has_input.get(edge["caller_function"]) and callee_has_dangerous.get(edge["callee_function"]):
                caller = function_of(next((c["address"] for c in callsites if c["role"] == "input" and c["function_id"] == edge["caller_function"]), 0))
                _ = caller
                chains.append(
                    {
                        "input_api": [c["api"] for c in callsites if c["role"] == "input" and c["function_id"] == edge["caller_function"]],
                        "input_source": "process_argument",
                        "function_id": edge["callee_function"],
                        "function_start": edge["callee_address"],
                        "dangerous_api": [c["api"] for c in callsites if c["role"] == "dangerous" and c["function_id"] == edge["callee_function"]][0],
                        "dangerous_category": [c["category"] for c in callsites if c["role"] == "dangerous" and c["function_id"] == edge["callee_function"]][0],
                        "callsite_address": next(
                            (c["address"] for c in callsites if c["role"] == "dangerous" and c["function_id"] == edge["callee_function"]),
                            None,
                        ),
                        "kind": "inter_function",
                    }
                )

        return {
            **base,
            "available": True,
            "dangerous_imports": {symbol: category for symbol, category in DANGEROUS_APIS.items() if any(e.get("symbol", "").casefold() == symbol for e in self.import_entries)},
            "input_imports": {symbol: source for symbol, source in INPUT_APIS.items() if any(e.get("symbol", "").casefold() == symbol for e in self.import_entries)},
            "functions": functions,
            "callsites": callsites,
            "call_edges": call_edges,
            "chains": chains,
        }


def _rip_memory_target(instruction: Any, operand: Any, mem_type: int, rip_register: int) -> int | None:
    if operand.type != mem_type or operand.mem.base != rip_register or operand.mem.index:
        return None
    return int(instruction.address + instruction.size + operand.mem.disp)


def _func_id(start_address: int) -> str:
    return f"f_{start_address:x}"
