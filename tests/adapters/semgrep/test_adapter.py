"""Unit tests for the Semgrep adapter (V0.5 first external engine).

Covers the adapter contract's fail-safe matrix: missing tool, timeout, error
exit, malformed JSON and success — plus health reporting and the provenance
mapping into EvidenceV2 (independence_group="semgrep").
"""

from vulnagent.adapters.semgrep.adapter import (
    CAPABILITIES,
    RunnerResult,
    SemgrepAdapter,
)
from vulnagent.contracts import EvidenceType, ToolExecutionRequest


class FakeRunner:
    """Injected CommandRunner; scriptable per command shape."""

    def __init__(self, *, version: RunnerResult | None = None, scan: RunnerResult | None = None) -> None:
        self.version_result = version or RunnerResult(returncode=0, stdout="1.90.0\n")
        self.scan_result = scan or RunnerResult(returncode=0, stdout="{}")
        self.calls: list[list[str]] = []

    def run(self, command, *, timeout_seconds: float, cwd: str | None = None) -> RunnerResult:
        self.calls.append(list(command))
        if "--version" in command:
            return self.version_result
        return self.scan_result


def make_request(target_path: str, **options) -> ToolExecutionRequest:
    return ToolExecutionRequest(
        run_id="run-1",
        task_id="task-1",
        capability="source.scan.semgrep",
        target_path=target_path,
        authorized=True,
        timeout_seconds=30,
        options=options,
    )


async def test_capabilities_are_declared() -> None:
    adapter = SemgrepAdapter(runner=FakeRunner())
    assert adapter.name == "semgrep"
    assert adapter.capabilities == CAPABILITIES


async def test_health_reports_available_with_version() -> None:
    adapter = SemgrepAdapter(runner=FakeRunner())
    health = await adapter.health()
    assert health.available is True
    assert health.version == "1.90.0"
    assert health.configured is True
    assert "source.scan.semgrep" in health.capabilities


async def test_health_reports_unavailable_when_tool_missing() -> None:
    adapter = SemgrepAdapter(
        runner=FakeRunner(
            version=RunnerResult(returncode=2, stderr="No module named 'semgrep'"),
        )
    )
    health = await adapter.health()
    assert health.available is False
    assert health.configured is False
    assert any("version probe failed" in note for note in health.notes)


async def test_health_reports_timeout() -> None:
    adapter = SemgrepAdapter(runner=FakeRunner(version=RunnerResult(timed_out=True)))
    health = await adapter.health()
    assert health.available is False
    assert any("timed out" in note for note in health.notes)


async def test_execute_target_not_found_is_failure_safe(tmp_path) -> None:
    adapter = SemgrepAdapter(runner=FakeRunner())
    result = await adapter.execute(make_request(str(tmp_path / "missing")))
    assert result.executed is False
    assert result.success is False
    assert "target not found" in (result.stderr_summary or "")


async def test_execute_missing_tool_is_failure_safe(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = SemgrepAdapter(
        runner=FakeRunner(scan=RunnerResult(error="executable not found: semgrep"))
    )
    result = await adapter.execute(make_request(str(target)))
    assert result.executed is True
    assert result.success is False
    assert result.metadata["error_kind"] == "execution_error"


async def test_execute_timeout_is_failure_safe(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = SemgrepAdapter(runner=FakeRunner(scan=RunnerResult(timed_out=True)))
    result = await adapter.execute(make_request(str(target), config="auto"))
    assert result.executed is True
    assert result.success is False
    assert result.metadata["error_kind"] == "timeout"


async def test_execute_timeout_with_complete_json_is_accepted_with_overrun(tmp_path) -> None:
    # The engine finished writing its JSON before the budget expired: accept
    # the full result and mark the overrun instead of discarding it.
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    payload = '{"results": []}'
    adapter = SemgrepAdapter(runner=FakeRunner(scan=RunnerResult(timed_out=True, stdout=payload)))
    result = await adapter.execute(make_request(str(target)))
    assert result.executed is True
    assert result.success is True
    assert result.metadata.get("overrun") is True
    assert result.metadata["finding_count"] == 0


async def test_execute_engine_error_exit_is_failure_safe(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = SemgrepAdapter(runner=FakeRunner(scan=RunnerResult(returncode=2, stderr="bad config")))
    result = await adapter.execute(make_request(str(target)))
    assert result.executed is True
    assert result.success is False
    assert result.metadata["error_kind"] == "nonzero_exit"
    assert result.metadata["returncode"] == 2


async def test_execute_malformed_json_is_failure_safe(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = SemgrepAdapter(runner=FakeRunner(scan=RunnerResult(returncode=0, stdout="<html>not json")))
    result = await adapter.execute(make_request(str(target)))
    assert result.executed is True
    assert result.success is False
    assert result.metadata["error_kind"] == "malformed_json"


async def test_execute_clean_scan_without_findings(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = SemgrepAdapter(runner=FakeRunner(scan=RunnerResult(returncode=0, stdout='{"results": []}')))
    result = await adapter.execute(make_request(str(target)))
    assert result.success is True
    assert result.findings == []
    assert result.facts == []
    assert result.metadata["finding_count"] == 0


async def test_execute_success_parses_findings_and_facts(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("import os\nos.system(input())\n")
    payload = """
    {
      "results": [
        {
          "check_id": "python.lang.security.audit.eval",
          "path": "app.py",
          "start": {"line": 2},
          "end": {"line": 2},
          "extra": {
            "message": "user input flows to os.system",
            "severity": "WARNING",
            "metadata": {"cwe": ["CWE-78"]},
            "language": "python"
          }
        }
      ]
    }
    """
    adapter = SemgrepAdapter(runner=FakeRunner(scan=RunnerResult(returncode=1, stdout=payload)))
    result = await adapter.execute(make_request(str(target)))
    assert result.success is True
    assert result.metadata["finding_count"] == 1
    finding = result.findings[0]
    assert finding.finding_id == "run-1-f0"
    assert finding.rule_id == "python.lang.security.audit.eval"
    assert finding.cwe_id == "CWE-78"
    assert finding.file_path == "app.py"
    assert finding.line_start == 2
    assert finding.severity == "WARNING"
    assert result.facts[0].fact_type == "match"
    assert result.facts[0].analysis_run_id == "run-1"


async def test_findings_to_evidence_maps_semgrep_provenance(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("import os\nos.system(input())\n")
    payload = """
    {
      "results": [
        {
          "check_id": "r1",
          "path": "app.py",
          "start": {"line": 2},
          "end": {"line": 2},
          "extra": {"message": "flow", "severity": "ERROR", "metadata": {"cwe": "CWE-78"}}
        }
      ]
    }
    """
    adapter = SemgrepAdapter(runner=FakeRunner(scan=RunnerResult(returncode=1, stdout=payload)))
    result = await adapter.execute(make_request(str(target)))
    evidence = adapter.findings_to_evidence(result, task_id="task-1", session_id="sess-1")
    assert len(evidence) == 1
    item = evidence[0]
    assert item.evidence_type is EvidenceType.SOURCE_LOCATION
    assert item.producer == "semgrep"
    assert item.analysis_run_id == "run-1"
    assert item.independence_group == "semgrep"
    assert item.derivation_id == "run-1-run-1-f0"
    assert item.reliability == 0.6
    assert item.data["cwe_id"] == "CWE-78"
    assert item.description == "flow"


async def test_new_run_id_is_unique_per_task() -> None:
    first = SemgrepAdapter.new_run_id("task-1")
    second = SemgrepAdapter.new_run_id("task-1")
    assert first != second
    assert first.startswith("task-1-semgrep-")
