"""Unit tests for the Bandit adapter (V0.6 third independent source engine).

Covers the fail-safe matrix (missing tool, timeout, error exit, malformed
JSON, success) plus health reporting, finding mapping and the provenance
mapping into EvidenceV2 (independence_group="bandit").
"""

from vulnagent.adapters.bandit.adapter import (
    CAPABILITIES,
    RunnerResult,
    BanditAdapter,
)
from vulnagent.contracts import EvidenceType, ToolExecutionRequest

SAMPLE_JSON = """{
  "errors": [],
  "results": [
    {
      "code": "    return subprocess.run(command, shell=True)\\n",
      "col_offset": 11,
      "filename": "app.py",
      "issue_confidence": "HIGH",
      "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
      "issue_severity": "HIGH",
      "issue_text": "subprocess call with shell=True identified, security issue.",
      "line_number": 8,
      "test_id": "B602",
      "test_name": "subprocess_popen_with_shell_equals_true"
    }
  ]
}"""


class FakeRunner:
    def __init__(self, *, version: RunnerResult | None = None, scan: RunnerResult | None = None) -> None:
        self.version_result = version or RunnerResult(returncode=0, stdout="1.9.4\n")
        self.scan_result = scan or RunnerResult(returncode=0, stdout=SAMPLE_JSON)
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
        capability="source.scan.bandit",
        target_path=target_path,
        authorized=True,
        timeout_seconds=30,
        options=options,
    )


async def test_capabilities_are_declared() -> None:
    adapter = BanditAdapter(runner=FakeRunner())
    assert adapter.name == "bandit"
    assert adapter.capabilities == CAPABILITIES


async def test_health_reports_available_with_version() -> None:
    adapter = BanditAdapter(runner=FakeRunner())
    health = await adapter.health()
    assert health.available is True
    assert health.version == "1.9.4"
    assert health.configured is True
    assert "source.scan.bandit" in health.capabilities


async def test_health_reports_unavailable_when_tool_missing() -> None:
    adapter = BanditAdapter(
        runner=FakeRunner(version=RunnerResult(returncode=2, stderr="No module named 'bandit'"))
    )
    health = await adapter.health()
    assert health.available is False
    assert any("version probe failed" in note for note in health.notes)


async def test_execute_target_not_found_is_failure_safe(tmp_path) -> None:
    adapter = BanditAdapter(runner=FakeRunner())
    result = await adapter.execute(make_request(str(tmp_path / "missing")))
    assert result.executed is False
    assert result.success is False
    assert "target not found" in (result.stderr_summary or "")


async def test_execute_missing_tool_is_failure_safe(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = BanditAdapter(
        runner=FakeRunner(scan=RunnerResult(error="executable not found: bandit"))
    )
    result = await adapter.execute(make_request(str(target)))
    assert result.executed is True
    assert result.success is False
    assert result.metadata["error_kind"] == "execution_error"


async def test_execute_timeout_is_failure_safe(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = BanditAdapter(runner=FakeRunner(scan=RunnerResult(timed_out=True)))
    result = await adapter.execute(make_request(str(target)))
    assert result.executed is True
    assert result.success is False
    assert result.metadata["error_kind"] == "timeout"


async def test_execute_nonzero_exit_is_failure_safe(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = BanditAdapter(runner=FakeRunner(scan=RunnerResult(returncode=2, stderr="bad config")))
    result = await adapter.execute(make_request(str(target)))
    assert result.executed is True
    assert result.success is False
    assert result.metadata["error_kind"] == "nonzero_exit"


async def test_execute_exit_1_is_a_clean_scan_with_findings(tmp_path) -> None:
    # bandit: 0 = clean, 1 = issues found; both are successful scans.
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = BanditAdapter(runner=FakeRunner(scan=RunnerResult(returncode=1, stdout=SAMPLE_JSON)))
    result = await adapter.execute(make_request(str(target)))
    assert result.success is True
    assert result.metadata["finding_count"] == 1


async def test_execute_malformed_json_is_failure_safe(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = BanditAdapter(runner=FakeRunner(scan=RunnerResult(returncode=0, stdout="{not json")))
    result = await adapter.execute(make_request(str(target)))
    assert result.executed is True
    assert result.success is False
    assert result.metadata["error_kind"] == "malformed_json"


async def test_execute_timeout_with_complete_json_is_accepted(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = BanditAdapter(runner=FakeRunner(scan=RunnerResult(timed_out=True, stdout=SAMPLE_JSON)))
    result = await adapter.execute(make_request(str(target)))
    assert result.success is True
    assert result.metadata["overrun"] is True
    assert result.metadata["finding_count"] == 1


async def test_execute_success_maps_finding_and_facts(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = BanditAdapter(runner=FakeRunner())
    result = await adapter.execute(make_request(str(target)))
    assert result.success is True
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "B602"
    assert finding.cwe_id == "CWE-78"
    assert finding.file_path == "app.py"
    assert finding.line_start == 8
    assert finding.severity == "HIGH"
    assert finding.raw["confidence"] == "HIGH"
    assert result.facts and result.facts[0].producer == "bandit"


async def test_evidence_mapping_uses_bandit_independence_group(tmp_path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n")
    adapter = BanditAdapter(runner=FakeRunner())
    result = await adapter.execute(make_request(str(target)))
    evidence = adapter.findings_to_evidence(result, task_id="task-1")
    assert len(evidence) == 1
    assert evidence[0].independence_group == "bandit"
    assert evidence[0].evidence_type is EvidenceType.SOURCE_LOCATION
    assert evidence[0].data["cwe_id"] == "CWE-78"
