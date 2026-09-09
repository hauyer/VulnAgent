"""V0.3 integration: real SourceProjectParser inside the closed loop.

Verifies the P1-composed application can accept the real P2 parser through
``CapabilityBundle`` without touching Orchestrator/Pipeline/AgentRuntime:
a SOURCE task on a real temp project completes and the parsed structure
reaches AnalysisContext while the rest of the chain still runs on mocks.
"""

from dataclasses import replace
from pathlib import Path

import pytest

from vulnagent.agent_runtime import AgentRoute
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.bootstrap import build_application, build_mock_capabilities
from vulnagent.contracts import (
    AgentMessageType,
    EventType,
    Target,
    TargetType,
    TaskStatus,
)


@pytest.mark.asyncio
async def test_real_source_parser_runs_inside_source_closed_loop(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "import os\n\ndef run():\n    return os.getcwd()\n",
        encoding="utf-8",
    )

    capabilities = replace(
        build_mock_capabilities(),
        source_parser=SourceProjectParser(),
    )
    services = build_application(capabilities)

    task = services.task_manager.create_task(
        Target(
            target_id="v03-source-target",
            path=str(tmp_path),
            target_type=TargetType.SOURCE,
        )
    )
    context = await services.orchestrator.run(task.task_id)

    assert context.task.status is TaskStatus.COMPLETED
    assert context.reports
    assert context.evidence
    assert context.findings

    # The real parser output must be observable in the trace.
    analysis_messages = [
        message
        for message in context.messages
        if message.message_type is AgentMessageType.ANALYSIS_RESULT
        and isinstance(message.payload.get("analysis"), dict)
    ]
    assert analysis_messages, "no ANALYSIS_RESULT message carried parser output"
    analysis = analysis_messages[0].payload["analysis"]
    assert analysis["metadata"]["parser"] == "source_project"
    assert analysis["languages"] == ["python"]
    assert analysis["files"] == ["main.py"]
    assert [symbol["qualified_name"] for symbol in analysis["symbols"]] == [
        "main.run"
    ]


@pytest.mark.asyncio
async def test_real_source_parser_on_mixed_project_does_not_abort_loop(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "def f():\n    return 1\n", encoding="utf-8"
    )
    (tmp_path / "util.c").write_text("int f(){return 0;}\n")

    capabilities = replace(
        build_mock_capabilities(),
        source_parser=SourceProjectParser(),
    )
    services = build_application(capabilities)
    task = services.task_manager.create_task(
        Target(
            target_id="v03-mixed-target",
            path=str(tmp_path),
            target_type=TargetType.SOURCE,
        )
    )
    context = await services.orchestrator.run(task.task_id)

    assert context.task.status is TaskStatus.COMPLETED
    started_routes = {
        event.payload["route"]
        for event in services.event_bus.list_by_task(task.task_id)
        if event.event_type is EventType.AGENT_STARTED
    }
    assert AgentRoute.SOURCE_ANALYSIS.value in started_routes
