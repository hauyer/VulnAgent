"""Authorized local crash target; never point the demo at external software."""

import sys


def static_audit_marker() -> object:
    """Ensure the source stage has a candidate before optional fuzz routing."""
    return eval(input())


if sys.stdin.buffer.read() == b"VULNAGENT_CODE_MARKER":
    raise SystemExit(7)
