"""Unit tests for the V0.5 tool adapter contracts."""

from vulnagent.contracts import (
    ArtifactRef,
    NormalizedToolFinding,
    ProgramFact,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolHealth,
)


def test_tool_health_defaults() -> None:
    health = ToolHealth(name="semgrep", available=False)
    assert health.version is None
    assert health.capabilities == []
    assert health.configured is False
    assert health.notes == []


def test_tool_execution_request_requires_authorization_explicitly() -> None:
    request = ToolExecutionRequest(
        run_id="r1",
        task_id="t1",
        capability="source.scan.semgrep",
        target_path="/tmp/proj",
    )
    assert request.authorized is False
    assert request.timeout_seconds == 60


def test_tool_execution_result_defaults_to_failure_safe() -> None:
    result = ToolExecutionResult(run_id="r1", capability="source.scan.semgrep", provider="semgrep")
    # The boundary contract: a result that was not executed must not look green.
    assert result.executed is False
    assert result.success is False
    assert result.findings == []
    assert result.facts == []


def test_result_carries_findings_facts_and_artifacts() -> None:
    result = ToolExecutionResult(
        run_id="r1",
        capability="source.scan.semgrep",
        provider="semgrep",
        executed=True,
        success=True,
        findings=[
            NormalizedToolFinding(
                finding_id="f1",
                rule_id="python.lang.security.audit.eval",
                severity="WARNING",
                cwe_id="CWE-95",
                file_path="app.py",
                line_start=12,
                line_end=12,
                message="audit: use of eval",
            )
        ],
        facts=[
            ProgramFact(
                fact_id="p1",
                fact_type="sink",
                language="python",
                file_path="app.py",
                function_name="run",
                line=12,
                producer="semgrep",
                analysis_run_id="r1",
            )
        ],
        artifacts=[
            ArtifactRef(
                artifact_id="a1",
                sha256="abc",
                media_type="application/json",
                path="artifacts/semgrep/r1.json",
                producer="semgrep",
            )
        ],
        stdout_summary="2 findings",
    )
    assert result.findings[0].cwe_id == "CWE-95"
    assert result.facts[0].fact_type == "sink"
    assert result.artifacts[0].artifact_id == "a1"


def test_result_serializes_to_json() -> None:
    result = ToolExecutionResult(run_id="r1", capability="source.scan.semgrep", provider="semgrep")
    payload = result.model_dump_json()
    assert '"run_id":"r1"' in payload
    assert '"success":false' in payload
