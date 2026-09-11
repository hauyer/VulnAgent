"""Canonical provider-neutral capability names for VulnAgent.

The values in this module describe logical system capabilities rather
than concrete implementations or vendors.

Examples:
    source.parse
    binary.inspect
    verification.verify

Concrete implementations are wired only by the application composition
root in ``bootstrap.py``.
"""

from enum import StrEnum


class CapabilityName(StrEnum):
    """Stable logical capability identifiers."""

    SOURCE_PARSE = "source.parse"
    SOURCE_AUDIT = "source.audit"

    BINARY_INSPECT = "binary.inspect"
    BINARY_LOGIC = "binary.logic"
    BINARY_OBFUSCATION = "binary.obfuscation"

    FUZZ_EXECUTE = "fuzz.execute"

    VERIFICATION_VERIFY = "verification.verify"

    REPORT_GENERATE = "report.generate"
