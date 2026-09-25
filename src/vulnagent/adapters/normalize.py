"""External engine normalization (WP2).

Two self-authored pieces complete the adapter boundary into the platform:

1. :func:`tool_result_status` maps a ``ToolExecutionResult`` onto the honest
   status vocabulary required by the practice plan:

       ok          - the engine really ran and produced findings
       empty       - the engine really ran and found nothing
       unavailable - the engine could not run (missing executable / not configured)
       timeout     - the engine was killed by the budget
       error       - the engine ran but failed (bad JSON, engine error exit)
       blocked     - the run was refused by an earlier guard (e.g. target missing)

   A missing tool is **never** reported as zero findings; that would pretend a
   scan happened when it did not.

2. :func:`external_finding_to_candidate` converts one normalized tool finding
   into a platform ``VulnerabilityCandidate`` carrying the fingerprint
   components (CWE, location, sink, rule id) so the candidate fusion engine can
   merge Native + Semgrep + Bandit findings about the same flaw into one fused
   candidate while keeping each source's independence group.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from vulnagent.contracts import (
    NormalizedToolFinding,
    ToolExecutionResult,
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)

# Some engines (notably Semgrep) put a long human-readable CWE line such as
# "CWE-78: Improper Neutralization ..." into the cwe field.  Fingerprinting
# needs the plain "CWE-78" so engines agree on the same flaw id.
_CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)

# Engines put the sink name in different places.  Bandit leaves a code snippet
# with the call; Semgrep writes "Found 'subprocess' function 'run' with
# 'shell=True'." into the message.  Extracting a comparable sink name lets the
# fusion engine merge the same flaw across engines.
_QUOTED_MODULE_FUNCTION = re.compile(r"'([A-Za-z_]\w*)' function '([A-Za-z_]\w*)'")
_CALL_PATTERN = re.compile(r"([A-Za-z_]\w*(?:\.\w+)*)\s*\(")
_FUNCTION_PATTERN = re.compile(r"function '([A-Za-z_]\w*)'")

# ToolExecutionResult.executed means "the subprocess was launched".  A missing
# executable surfaces as error_kind="execution_error" with "not found" in the
# detail.  Mapping it to "unavailable" keeps "ran with no findings" distinct
# from "never ran".
_NOT_FOUND_MARKERS = ("not found", "executable not found", "no module named")


def tool_result_status(result: ToolExecutionResult) -> str:
    """Classify a tool run into the honest status vocabulary.

    Returns one of ``ok`` / ``empty`` / ``unavailable`` / ``timeout`` /
    ``error`` / ``blocked``.
    """

    if not result.executed:
        if "target not found" in (result.stderr_summary or ""):
            return "blocked"
        return "unavailable"
    if result.success:
        return "ok" if result.findings else "empty"

    error_kind = str(result.metadata.get("error_kind") or "")
    if error_kind == "timeout":
        return "timeout"
    if error_kind == "execution_error":
        detail = " ".join(
            str(item)
            for item in (
                result.metadata.get("error"),
                result.stderr_summary,
            )
            if item
        ).casefold()
        if any(marker in detail for marker in _NOT_FOUND_MARKERS):
            return "unavailable"
        return "error"
    return "error"


def tool_result_summary(result: ToolExecutionResult) -> dict[str, Any]:
    """Compact, artifact-free run summary for tool_runs.jsonl records."""

    return {
        "run_id": result.run_id,
        "capability": result.capability,
        "provider": result.provider,
        "status": tool_result_status(result),
        "success": result.success,
        "executed": result.executed,
        "finding_count": len(result.findings),
        "fact_count": len(result.facts),
        "error_kind": result.metadata.get("error_kind"),
        "stderr_summary": result.stderr_summary,
        "elapsed_ms": (
            round(
                (result.finished_at - result.started_at).total_seconds() * 1000
            )
            if result.finished_at is not None
            else None
        ),
    }


def external_finding_to_candidate(
    result: ToolExecutionResult,
    finding: NormalizedToolFinding,
    *,
    task_id: str,
    target_id: str,
    base_reliability: float = 0.55,
) -> VulnerabilityCandidate:
    """Convert one normalized external finding into a platform candidate.

    The candidate stays ``CANDIDATE`` (discovery modules never confirm).  Its
    ``metadata`` carries the fingerprint components the fusion engine reads:
    ``sink``, ``rule_id``, ``source_kinds`` and the provider's raw confidence.
    """

    confidence = base_reliability
    raw = finding.raw or {}
    if isinstance(raw.get("confidence"), (int, float)):
        confidence = max(0.0, min(1.0, float(raw["confidence"]) * base_reliability))

    cwe = _normalize_cwe(finding.cwe_id)
    vulnerability_type = _vulnerability_type(cwe, finding.message, finding.rule_id)
    sink = _extract_sink(finding.message, raw)

    return VulnerabilityCandidate(
        vulnerability_id=f"{result.run_id}-{finding.finding_id}",
        task_id=task_id,
        title=finding.message or (finding.rule_name or finding.rule_id or "external finding"),
        vulnerability_type=vulnerability_type,
        cwe_id=cwe,
        description=finding.message or "no description provided by the engine",
        target_id=target_id,
        location=VulnerabilityLocation(
            file_path=finding.file_path,
            function_name=finding.function_name,
            line_start=finding.line_start,
            line_end=finding.line_end,
        ),
        source_agent=result.provider,
        source_type="external_tool",
        producer=result.provider,
        confidence=round(confidence, 3),
        severity=finding.severity,
        evidence_ids=[],
        status=VulnerabilityStatus.CANDIDATE,
        metadata={
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "sink": sink,
            "source_kinds": raw.get("source_kinds"),
            "analysis_run_id": result.run_id,
            "provider_confidence": raw.get("confidence"),
            "raw_message": finding.message,
            "mapped_by": "vulnagent.external_normalizer",
        },
    )


def new_candidate_id(task_id: str, provider: str) -> str:
    """Allocate a unique external candidate id for one provider."""

    return f"{task_id}-{provider}-{uuid.uuid4().hex[:12]}"


def _extract_sink(message: str, raw: dict[str, Any]) -> str | None:
    """Derive a comparable sink name from an engine finding.

    Priority: explicit raw sink -> module-qualified name from a Semgrep-style
    message (``'subprocess' function 'run'``) -> first call expression in the
    message or Bandit code snippet -> bare function mention.  Returning None is
    fine: the fusion loose key still degrades gracefully, but the more engines
    agree on a sink the more reliably the same flaw fuses into one candidate.
    """

    explicit = raw.get("sink")
    if explicit:
        return str(explicit)

    text = " ".join(
        str(item)
        for item in (message, raw.get("code"), raw.get("more_info"))
        if item
    )
    module_function = _QUOTED_MODULE_FUNCTION.search(text)
    if module_function:
        return f"{module_function.group(1)}.{module_function.group(2)}"

    # The message is the most reliable place for the sink call; fall back to
    # the code snippet only when the message names no call.
    for source, prefer_last in (
        (str(message), False),
        (str(raw.get("code") or ""), True),
    ):
        calls = list(_CALL_PATTERN.finditer(source))
        if calls:
            match = calls[-1] if prefer_last else calls[0]
            return match.group(1)

    function = _FUNCTION_PATTERN.search(text)
    if function:
        return function.group(1)
    return None


def _normalize_cwe(cwe: str | None) -> str | None:
    """Reduce an engine CWE string to the canonical ``CWE-N`` identifier."""

    if not cwe:
        return None
    match = _CWE_PATTERN.search(cwe)
    if match:
        return match.group(0).upper()
    return cwe


def _vulnerability_type(cwe: str | None, message: str, rule_id: str | None) -> str:
    """Derive a stable vulnerability_type from CWE or the rule id."""

    if cwe:
        return cwe
    text = " ".join(
        item for item in (message, rule_id) if item
    ).casefold()
    for needle, value in (
        ("command", "command_injection"),
        ("sql", "sql_injection"),
        ("path", "path_traversal"),
        ("deserial", "unsafe_deserialization"),
        ("eval", "dynamic_code_execution"),
        ("exec", "command_injection"),
    ):
        if needle in text:
            return value
    return "external_finding"
