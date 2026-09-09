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


__all__ = ["AuditRule"]
