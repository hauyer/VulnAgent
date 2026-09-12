"""Internal rule catalogue for the Python source auditor.

Rules describe VulnAgent-owned findings.  They deliberately contain no
third-party scanner output and are not public Contracts.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuditRule:
    """Metadata used to turn one explainable match into a candidate."""

    rule_id: str
    category: str
    title: str
    vulnerability_type: str
    cwe_id: str
    severity: str
    tainted_confidence: float
    dynamic_confidence: float


COMMAND_INJECTION = AuditRule(
    rule_id="VA-PY-CMD-001",
    category="command",
    title="Potential command injection",
    vulnerability_type="command_injection",
    cwe_id="CWE-78",
    severity="HIGH",
    tainted_confidence=0.84,
    dynamic_confidence=0.62,
)

SQL_INJECTION = AuditRule(
    rule_id="VA-PY-SQL-001",
    category="sql",
    title="Potential SQL injection",
    vulnerability_type="sql_injection",
    cwe_id="CWE-89",
    severity="HIGH",
    tainted_confidence=0.82,
    dynamic_confidence=0.58,
)

PATH_TRAVERSAL = AuditRule(
    rule_id="VA-PY-PATH-001",
    category="path",
    title="Potential path traversal",
    vulnerability_type="path_traversal",
    cwe_id="CWE-22",
    severity="MEDIUM",
    tainted_confidence=0.78,
    dynamic_confidence=0.55,
)

UNSAFE_DESERIALIZATION = AuditRule(
    rule_id="VA-PY-DESER-001",
    category="deserialization",
    title="Potential unsafe deserialization",
    vulnerability_type="unsafe_deserialization",
    cwe_id="CWE-502",
    severity="HIGH",
    tainted_confidence=0.86,
    dynamic_confidence=0.65,
)

DYNAMIC_CODE_EXECUTION = AuditRule(
    rule_id="VA-PY-EVAL-001",
    category="code_execution",
    title="Potential dynamic code execution",
    vulnerability_type="dynamic_code_execution",
    cwe_id="CWE-95",
    severity="HIGH",
    tainted_confidence=0.88,
    dynamic_confidence=0.68,
)

NATIVE_DANGEROUS_COPY = AuditRule(
    rule_id="VA-NATIVE-MEM-001",
    category="memory",
    title="Potential native buffer overflow",
    vulnerability_type="buffer_overflow",
    cwe_id="CWE-120",
    severity="HIGH",
    tainted_confidence=0.86,
    dynamic_confidence=0.68,
)

NATIVE_INTEGER_OVERFLOW = AuditRule(
    rule_id="VA-NATIVE-INT-001",
    category="integer",
    title="Potential integer overflow in size calculation",
    vulnerability_type="integer_overflow",
    cwe_id="CWE-190",
    severity="HIGH",
    tainted_confidence=0.82,
    dynamic_confidence=0.62,
)

NATIVE_ARRAY_BOUNDS = AuditRule(
    rule_id="VA-NATIVE-BOUNDS-001",
    category="bounds",
    title="Potential array index out of bounds",
    vulnerability_type="array_out_of_bounds",
    cwe_id="CWE-129",
    severity="HIGH",
    tainted_confidence=0.82,
    dynamic_confidence=0.60,
)

NATIVE_INPUT_VALIDATION = AuditRule(
    rule_id="VA-NATIVE-INPUT-001",
    category="input_validation",
    title="Potential missing input validation",
    vulnerability_type="input_validation_missing",
    cwe_id="CWE-20",
    severity="MEDIUM",
    tainted_confidence=0.74,
    dynamic_confidence=0.54,
)

NATIVE_NULL_DEREFERENCE = AuditRule(
    rule_id="VA-NATIVE-NULL-001",
    category="null_safety",
    title="Potential null pointer dereference",
    vulnerability_type="null_pointer_dereference",
    cwe_id="CWE-476",
    severity="MEDIUM",
    tainted_confidence=0.72,
    dynamic_confidence=0.52,
)

NATIVE_RESOURCE_LEAK = AuditRule(
    rule_id="VA-NATIVE-RESOURCE-001",
    category="resource_lifecycle",
    title="Potential resource leak",
    vulnerability_type="resource_leak",
    cwe_id="CWE-772",
    severity="MEDIUM",
    tainted_confidence=0.68,
    dynamic_confidence=0.58,
)

NATIVE_INTERFACE_ACCESS = AuditRule(
    rule_id="VA-NATIVE-ACCESS-001",
    category="access_control",
    title="Potential local interface access-control omission",
    vulnerability_type="interface_access_control_missing",
    cwe_id="CWE-862",
    severity="HIGH",
    tainted_confidence=0.70,
    dynamic_confidence=0.55,
)

NATIVE_CONFIG_AUTHORIZATION = AuditRule(
    rule_id="VA-NATIVE-CONFIG-001",
    category="configuration_authorization",
    title="Potential configuration authorization omission",
    vulnerability_type="configuration_authorization_missing",
    cwe_id="CWE-863",
    severity="HIGH",
    tainted_confidence=0.72,
    dynamic_confidence=0.56,
)


__all__ = [
    "AuditRule",
    "NATIVE_ARRAY_BOUNDS",
    "NATIVE_DANGEROUS_COPY",
    "NATIVE_INPUT_VALIDATION",
    "NATIVE_INTEGER_OVERFLOW",
    "NATIVE_NULL_DEREFERENCE",
    "NATIVE_RESOURCE_LEAK",
    "NATIVE_INTERFACE_ACCESS",
    "NATIVE_CONFIG_AUTHORIZATION",
]
