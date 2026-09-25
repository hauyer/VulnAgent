"""Tests for external engine normalization (WP2).

The honest-status vocabulary is the WP2 contract: a missing engine is
``unavailable``, a real run with no findings is ``empty``, and neither may be
presented as zero findings from a scan that never happened.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from vulnagent.adapters.normalize import (
    external_finding_to_candidate,
    new_candidate_id,
    tool_result_status,
    tool_result_summary,
)
from vulnagent.analyzers.source.fusion.engine import CandidateFusionEngine
from vulnagent.contracts import (
    NormalizedToolFinding,
    ToolExecutionRequest,
    ToolExecutionResult,
    VulnerabilityStatus,
)
from vulnagent.contracts.common import utc_now


def _result(**overrides) -> ToolExecutionResult:
    request = ToolExecutionRequest(
        run_id="run-1",
        task_id="task-1",
        capability="source.scan.semgrep",
        target_path="app.py",
        authorized=True,
    )
    values = dict(
        run_id=request.run_id,
        capability=request.capability,
        provider="semgrep",
        started_at=utc_now(),
    )
    values.update(overrides)
    result = ToolExecutionResult(**values)
    if result.finished_at is not None and result.started_at is not None:
        pass
    return result


def _finding(rule_id: str = "r1", line: int = 5, cwe: str | None = "CWE-78") -> NormalizedToolFinding:
    return NormalizedToolFinding(
        finding_id="f0",
        rule_id=rule_id,
        rule_name=rule_id,
        severity="WARNING",
        cwe_id=cwe,
        file_path="app.py",
        line_start=line,
        line_end=line,
        message="user input flows to dangerous sink",
        raw={"sink": "subprocess.call", "confidence": 0.8},
    )


def test_status_ok_when_engine_ran_and_found() -> None:
    result = _result(
        executed=True,
        success=True,
        findings=[_finding()],
        finished_at=utc_now(),
    )
    assert tool_result_status(result) == "ok"


def test_status_empty_when_engine_ran_and_found_nothing() -> None:
    result = _result(
        executed=True,
        success=True,
        findings=[],
        finished_at=utc_now(),
    )
    assert tool_result_status(result) == "empty"


def test_status_unavailable_for_missing_executable() -> None:
    result = _result(
        executed=True,
        success=False,
        findings=[],
        metadata={"error_kind": "execution_error", "error": "executable not found: semgrep"},
    )
    assert tool_result_status(result) == "unavailable"


def test_status_unavailable_for_module_not_found() -> None:
    result = _result(
        executed=True,
        success=False,
        metadata={"error_kind": "execution_error"},
        stderr_summary="No module named 'semgrep'",
    )
    assert tool_result_status(result) == "unavailable"


def test_status_timeout() -> None:
    result = _result(
        executed=True,
        success=False,
        metadata={"error_kind": "timeout"},
    )
    assert tool_result_status(result) == "timeout"


def test_status_error_for_malformed_json() -> None:
    result = _result(
        executed=True,
        success=False,
        metadata={"error_kind": "malformed_json", "error": "invalid json"},
    )
    assert tool_result_status(result) == "error"


def test_status_error_for_engine_error_exit() -> None:
    result = _result(
        executed=True,
        success=False,
        metadata={"error_kind": "nonzero_exit", "returncode": 2},
    )
    assert tool_result_status(result) == "error"


def test_status_blocked_when_target_missing() -> None:
    result = _result(
        executed=False,
        success=False,
        stderr_summary="target not found: app.py",
    )
    assert tool_result_status(result) == "blocked"


def test_status_unavailable_when_never_executed_without_reason() -> None:
    result = _result(executed=False, success=False)
    assert tool_result_status(result) == "unavailable"


def test_summary_keeps_honest_status_and_counts() -> None:
    result = _result(
        executed=True,
        success=True,
        findings=[_finding()],
        started_at=utc_now(),
        finished_at=utc_now() + timedelta(seconds=1),
    )
    summary = tool_result_summary(result)
    assert summary["status"] == "ok"
    assert summary["finding_count"] == 1
    assert summary["elapsed_ms"] == 1000


def test_external_finding_maps_to_candidate() -> None:
    result = _result(executed=True, success=True, findings=[_finding()])
    candidate = external_finding_to_candidate(
        result, _finding(), task_id="task-1", target_id="t1"
    )
    assert candidate.status is VulnerabilityStatus.CANDIDATE
    assert candidate.source_agent == "semgrep"
    assert candidate.producer == "semgrep"
    assert candidate.cwe_id == "CWE-78"
    assert candidate.metadata["sink"] == "subprocess.call"
    assert candidate.metadata["rule_id"] == "r1"
    assert candidate.confidence > 0.0


def test_cwe_description_is_reduced_to_canonical_id() -> None:
    """Semgrep-style long CWE lines must normalize to the plain CWE-N id."""

    result = _result(executed=True, success=True)
    finding = _finding(cwe="CWE-78: Improper Neutralization of Special Elements "
                            "used in an OS Command ('OS Command Injection')")
    candidate = external_finding_to_candidate(
        result, finding, task_id="task-1", target_id="t1"
    )
    assert candidate.cwe_id == "CWE-78"
    assert candidate.vulnerability_type == "CWE-78"


def test_unknown_cwe_text_is_kept_as_is() -> None:
    result = _result(executed=True, success=True)
    finding = _finding(cwe="no-cwe-provided")
    candidate = external_finding_to_candidate(
        result, finding, task_id="task-1", target_id="t1"
    )
    assert candidate.cwe_id == "no-cwe-provided"


def test_sink_extracted_from_semgrep_style_message() -> None:
    """Semgrep message names module and function separately."""

    result = _result(executed=True, success=True)
    finding = NormalizedToolFinding(
        finding_id="f0",
        rule_id="subprocess-shell-true",
        severity="WARNING",
        cwe_id="CWE-78",
        file_path="app.py",
        line_start=8,
        message="Found 'subprocess' function 'run' with 'shell=True'.",
        raw={},
    )
    candidate = external_finding_to_candidate(
        result, finding, task_id="task-1", target_id="t1"
    )
    assert candidate.metadata["sink"] == "subprocess.run"


def test_sink_extracted_from_bandit_code_snippet() -> None:
    """Bandit leaves the call in the raw code snippet."""

    result = _result(executed=True, success=True)
    finding = NormalizedToolFinding(
        finding_id="f0",
        rule_id="B602",
        severity="MEDIUM",
        cwe_id="CWE-78",
        file_path="app.py",
        line_start=8,
        message="subprocess call with shell=True identified, security issue.",
        raw={"code": "7     command = input(\"command: \")\n8     return subprocess.run(command, shell=True, check=False, text=True)\n"},
    )
    candidate = external_finding_to_candidate(
        result, finding, task_id="task-1", target_id="t1"
    )
    assert candidate.metadata["sink"] == "subprocess.run"


def test_sink_falls_back_to_none_when_not_derivable() -> None:
    result = _result(executed=True, success=True)
    finding = NormalizedToolFinding(
        finding_id="f0",
        rule_id="B404",
        severity="LOW",
        cwe_id="CWE-78",
        file_path="app.py",
        line_start=3,
        message="Consider possible security implications of importing subprocess.",
        raw={"code": "import subprocess\n"},
    )
    candidate = external_finding_to_candidate(
        result, finding, task_id="task-1", target_id="t1"
    )
    assert candidate.metadata["sink"] is None


def test_fusion_merges_native_semgrep_bandit_into_one_candidate(tmp_path: Path) -> None:
    """Three engines flagging the same line must fuse to one candidate."""

    base = str(tmp_path)
    native = external_finding_to_candidate(
        _result(executed=True, success=True, findings=[_finding(rule_id="native", cwe="CWE-78")]),
        _finding(rule_id="native", cwe="CWE-78"),
        task_id="task-1",
        target_id="t1",
    )
    semgrep = external_finding_to_candidate(
        _result(provider="semgrep", run_id="r-sg", executed=True, success=True),
        _finding(rule_id="sg-rule", cwe="CWE-78"),
        task_id="task-1",
        target_id="t1",
    )
    bandit = external_finding_to_candidate(
        _result(provider="bandit", run_id="r-ba", executed=True, success=True),
        _finding(rule_id="ba-rule", cwe="CWE-78"),
        task_id="task-1",
        target_id="t1",
    )
    engine = CandidateFusionEngine()
    fused = engine.fuse(
        [native, semgrep, bandit],
        independence_groups={
            native.vulnerability_id: "native",
            semgrep.vulnerability_id: "semgrep",
            bandit.vulnerability_id: "bandit",
        },
        base_path=base,
    )
    assert len(fused) == 1
    assert len(fused[0].source_candidates) == 3
    assert set(fused[0].supporting_independence_groups) == {"native", "semgrep", "bandit"}


def test_fusion_keeps_distinct_flaws_apart(tmp_path: Path) -> None:
    """Different lines / sinks must not merge into one candidate."""

    base = str(tmp_path)
    a = external_finding_to_candidate(
        _result(provider="semgrep", run_id="r-a", executed=True, success=True),
        _finding(rule_id="a", cwe="CWE-78", line=5),
        task_id="task-1",
        target_id="t1",
    )
    b = external_finding_to_candidate(
        _result(provider="bandit", run_id="r-b", executed=True, success=True),
        _finding(rule_id="b", cwe="CWE-22", line=40),
        task_id="task-1",
        target_id="t1",
    )
    fused = CandidateFusionEngine().fuse([a, b], base_path=base)
    assert len(fused) == 2


def test_same_engine_derived_findings_do_not_inflate_independence(tmp_path: Path) -> None:
    """Two findings from one semgrep run are one independence group."""

    base = str(tmp_path)
    first = external_finding_to_candidate(
        _result(provider="semgrep", run_id="r-sg", executed=True, success=True),
        _finding(rule_id="sg-1", cwe="CWE-78", line=5),
        task_id="task-1",
        target_id="t1",
    )
    second = external_finding_to_candidate(
        _result(provider="semgrep", run_id="r-sg", executed=True, success=True),
        _finding(rule_id="sg-2", cwe="CWE-78", line=6),
        task_id="task-1",
        target_id="t1",
    )
    fused = CandidateFusionEngine().fuse(
        [first, second],
        independence_groups={
            first.vulnerability_id: "semgrep",
            second.vulnerability_id: "semgrep",
        },
        base_path=base,
    )
    assert len(fused) == 1
    assert fused[0].supporting_independence_groups == ["semgrep"]


def test_new_candidate_id_is_unique() -> None:
    assert new_candidate_id("t1", "semgrep") != new_candidate_id("t1", "semgrep")
