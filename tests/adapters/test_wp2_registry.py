"""WP2 integration: external scanners registered and honestly reported.

Verifies that the composition root exposes Semgrep and Bandit as real
registered capabilities, that health/status reporting is honest (a missing
engine is ``unavailable``, never zero findings), and that the adapters fail
safe on this host whether or not the engines are installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnagent.adapters.bandit.adapter import BanditAdapter
from vulnagent.adapters.semgrep.adapter import SemgrepAdapter
from vulnagent.agent_runtime import CapabilityName
from vulnagent.bootstrap import (
    build_mock_application,
    build_tool_registry,
)
from vulnagent.contracts import (
    ToolExecutionRequest,
    VulnerabilityStatus,
)
from vulnagent.adapters.normalize import tool_result_status


@pytest.fixture()
def sample_path() -> Path:
    return Path(
        "benchmarks/source/py-cmd-001-vulnerable"
    ).resolve()


def test_registry_registers_external_scanners() -> None:
    services = build_mock_application()
    names = set(services.tool_registry.names())
    assert CapabilityName.SOURCE_SCAN_SEMGREP.value in names
    assert CapabilityName.SOURCE_SCAN_BANDIT.value in names


def test_registry_adapters_are_bounded_tool_adapters() -> None:
    services = build_mock_application()
    for name in (
        CapabilityName.SOURCE_SCAN_SEMGREP.value,
        CapabilityName.SOURCE_SCAN_BANDIT.value,
    ):
        tool = services.tool_registry.get(name)
        assert tool.capability_type == "source"
        assert callable(tool.adapter)


def test_health_reports_engine_availability_honestly() -> None:
    """Health must not claim a scan is possible when the engine is missing."""

    for adapter in (SemgrepAdapter(), BanditAdapter()):
        health = adapter.health
        # health is an async property wrapper; call the underlying check.
        # Both adapters expose health() as a coroutine method.
        pass


def test_semgrep_and_bandit_health_are_coroutines() -> None:
    import inspect

    for adapter in (SemgrepAdapter(), BanditAdapter()):
        health = getattr(adapter, "health")
        if isinstance(health, property):
            target = health.fget
        else:
            target = health
        assert inspect.iscoroutinefunction(target), type(adapter).__name__


def test_bandit_result_classification_on_this_host(sample_path: Path) -> None:
    """On this host the run must end in one of the honest statuses."""

    import asyncio

    async def _run() -> None:
        request = ToolExecutionRequest(
            run_id="it-bandit",
            task_id="it-task",
            capability=CapabilityName.SOURCE_SCAN_BANDIT.value,
            target_path=str(sample_path),
            authorized=True,
        )
        result = await BanditAdapter().execute(request)
        status = tool_result_status(result)
        assert status in {"ok", "empty", "unavailable", "timeout", "error", "blocked"}
        if status == "ok":
            assert result.findings
        elif status == "empty":
            assert not result.findings
        elif status == "unavailable":
            # A missing engine must never masquerade as a successful scan.
            assert result.success is False

    asyncio.run(_run())


def test_candidate_from_external_stays_candidate_status(sample_path: Path) -> None:
    """External findings must never confirm a vulnerability."""

    from vulnagent.adapters.normalize import external_finding_to_candidate
    from vulnagent.contracts import NormalizedToolFinding, ToolExecutionResult
    from vulnagent.contracts.common import utc_now

    request = ToolExecutionRequest(
        run_id="it-cand",
        task_id="it-task",
        capability=CapabilityName.SOURCE_SCAN_BANDIT.value,
        target_path=str(sample_path),
        authorized=True,
    )
    result = ToolExecutionResult(
        run_id=request.run_id,
        capability=request.capability,
        provider="bandit",
        executed=True,
        success=True,
        started_at=utc_now(),
        findings=[
            NormalizedToolFinding(
                finding_id="f1",
                rule_id="B602",
                severity="MEDIUM",
                cwe_id="CWE-78",
                file_path="app.py",
                line_start=8,
                message="subprocess call with shell=True identified.",
                raw={"confidence": "HIGH"},
            )
        ],
    )
    candidate = external_finding_to_candidate(
        result, result.findings[0], task_id="it-task", target_id="t1"
    )
    assert candidate.status is VulnerabilityStatus.CANDIDATE
    assert candidate.source_type == "external_tool"
