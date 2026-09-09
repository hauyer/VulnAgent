"""Stable V0.2 mock system baseline through the public composition root."""

from collections.abc import Mapping, Sequence
from typing import get_type_hints

import pytest

from vulnagent.agent_runtime import AgentRoute, RuntimePolicy, RuntimeState
from vulnagent.agents.base import BaseAgent
from vulnagent.agents.registry import AgentRegistry
from vulnagent.bootstrap import (
    build_application,
    build_agent_registry,
    build_mock_application,
    build_mock_capabilities,
)
from vulnagent.contracts import (
    AgentMessageType,
    AgentResult,
    AnalysisContext,
    EventType,
    ModuleExecutionError,
    Target,
    TargetType,
    Task,
    TaskStatus,
    VulnerabilityStatus,
)


PRIVATE_TRACE_FIELDS = {
    "chain_of_thought",
    "private_reasoning",
    "hidden_reasoning",
    "raw_cot",
    "reasoning_tokens",
}

RUNTIME_BUSINESS_FIELDS = {
    "finding",
    "findings",
    "evidence",
    "verification",
    "verifications",
    "report",
    "reports",
    "vulnerabilities",
    "analysis_context",
}


def nested_keys(value: object) -> set[str]:
    if isinstance(value, Mapping):
        return {
            str(key).casefold().replace("-", "_")
            for key in value
        } | {
            nested
            for item in value.values()
            for nested in nested_keys(item)
        }
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return {
            nested
            for item in value
            for nested in nested_keys(item)
        }
    return set()


async def run_mock(
    target_type: TargetType,
    *,
    metadata: dict[str, object] | None = None,
):
    services = build_mock_application()
    task = services.task_manager.create_task(
        Target(
            target_id=f"{target_type.value}-target",
            path="safe-mock-fixture",
            target_type=target_type,
            metadata=metadata or {},
        )
    )
    context = await services.orchestrator.run(task.task_id)
    events = services.event_bus.list_by_task(task.task_id)
    routes = [
        event.payload["route"]
        for event in events
        if event.event_type is EventType.AGENT_STARTED
    ]
    return services, context, events, routes


def assert_closed_loop(
    services,
    context: AnalysisContext,
    events,
    routes: list[str],
    expected_analysis_route: AgentRoute,
) -> None:
    stored = services.task_manager.get_task(context.task.task_id)
    assert stored == context.task
    assert context.task.status is TaskStatus.COMPLETED
    assert context.reports
    assert context.evidence
    assert services.evidence_store.list_by_task(context.task.task_id)
    assert context.findings
    assert all(
        finding.status in {
            VulnerabilityStatus.CONFIRMED,
            VulnerabilityStatus.REJECTED,
            VulnerabilityStatus.UNCERTAIN,
        }
        for finding in context.findings
    )
    assert any(
        message.message_type is AgentMessageType.VERIFICATION_RESULT
        for message in context.messages
    )

    assert routes == [
        AgentRoute.PLANNER.value,
        expected_analysis_route.value,
        AgentRoute.VERIFICATION.value,
        AgentRoute.REVIEWER.value,
        AgentRoute.REPORT.value,
    ]
    assert len(routes) <= services.runtime_policy.max_agent_steps

    event_types = {event.event_type for event in events}
    assert {
        EventType.TASK_STARTED,
        EventType.AGENT_ROUTED,
        EventType.AGENT_STARTED,
        EventType.AGENT_FINISHED,
        EventType.CANDIDATE_CREATED,
        EventType.VERIFICATION_STARTED,
        EventType.REVIEW_COMPLETED,
        EventType.REPORT_GENERATED,
        EventType.EVIDENCE_ADDED,
    }.issubset(event_types)

    assert set(get_type_hints(RuntimeState)).isdisjoint(
        RUNTIME_BUSINESS_FIELDS
    )
    assert nested_keys(
        [event.payload for event in events]
    ).isdisjoint(PRIVATE_TRACE_FIELDS)
    assert nested_keys(
        [message.payload for message in context.messages]
    ).isdisjoint(PRIVATE_TRACE_FIELDS)


async def test_source_mock_closed_loop() -> None:
    services, context, events, routes = await run_mock(TargetType.SOURCE)
    assert_closed_loop(
        services,
        context,
        events,
        routes,
        AgentRoute.SOURCE_ANALYSIS,
    )


async def test_binary_mock_closed_loop() -> None:
    services, context, events, routes = await run_mock(TargetType.BINARY)
    assert_closed_loop(
        services,
        context,
        events,
        routes,
        AgentRoute.BINARY_ANALYSIS,
    )


async def test_authorized_dynamic_validation_routes_through_mock_fuzz() -> None:
    services, context, events, routes = await run_mock(
        TargetType.SOURCE,
        metadata={
            "fuzz_authorized": True,
            "dynamic_validation": True,
        },
    )

    assert routes == [
        AgentRoute.PLANNER.value,
        AgentRoute.SOURCE_ANALYSIS.value,
        AgentRoute.FUZZ.value,
        AgentRoute.VERIFICATION.value,
        AgentRoute.REVIEWER.value,
        AgentRoute.REPORT.value,
    ]
    assert context.task.status is TaskStatus.COMPLETED
    assert any(
        event.event_type is EventType.AGENT_ROUTED
        and event.payload.get("route") == AgentRoute.FUZZ.value
        for event in events
    )
    assert len(routes) <= services.runtime_policy.max_agent_steps


async def test_unauthorized_target_never_routes_to_fuzz() -> None:
    _, context, _, routes = await run_mock(
        TargetType.SOURCE,
        metadata={
            "fuzz_authorized": False,
            "dynamic_validation": True,
        },
    )

    assert AgentRoute.FUZZ.value not in routes
    assert context.task.status is TaskStatus.COMPLETED


async def test_bounded_truncation_marks_completed_and_persists_termination() -> None:
    """A step-limited run ends deterministically with a report but must be
    durably distinguishable from a full execution via task metadata."""
    services = build_application(
        build_mock_capabilities(),
        runtime_policy=RuntimePolicy(max_agent_steps=2),
    )
    task = services.task_manager.create_task(
        Target(
            target_id="truncated-target",
            path="safe-mock-fixture",
            target_type=TargetType.SOURCE,
        )
    )
    context = await services.orchestrator.run(task.task_id)

    # The bounded router reserves the final slot for REPORT, so the lifecycle
    # still reaches a report and completes; it must not be marked FAILED.
    assert context.task.status is TaskStatus.COMPLETED
    assert context.reports

    stored = services.task_manager.get_task(task.task_id)
    termination = stored.metadata["termination"]
    assert termination["step_limit_reached"] is True
    assert termination["execution_failed"] is False
    assert termination["agent_steps_executed"] <= 2
    assert "report" in termination["route_history"]
    assert context.metadata["termination"]["step_limit_reached"] is True


async def test_normal_run_persists_termination_metadata_not_truncated() -> None:
    """A complete run records structured termination flags with no truncation."""
    services = build_mock_application()
    task = services.task_manager.create_task(
        Target(
            target_id="full-target",
            path="safe-mock-fixture",
            target_type=TargetType.SOURCE,
        )
    )
    context = await services.orchestrator.run(task.task_id)

    assert context.task.status is TaskStatus.COMPLETED
    stored = services.task_manager.get_task(task.task_id)
    termination = stored.metadata["termination"]
    assert termination["step_limit_reached"] is False
    assert termination["fallback_used"] is False
    assert termination["execution_failed"] is False
    assert termination["analysis_retries"] == 0
    assert termination["agent_steps_executed"] <= services.runtime_policy.max_agent_steps
    assert context.metadata["termination"] == termination


class FailingSourceAgent(BaseAgent):
    name = "failing_source"

    async def run(
        self,
        task: Task,
        context: AnalysisContext,
    ) -> AgentResult:
        raise RuntimeError("synthetic source failure")


class EmptyReportAgent(BaseAgent):
    name = "empty_report"

    async def run(
        self,
        task: Task,
        context: AnalysisContext,
    ) -> AgentResult:
        return AgentResult(agent_name=self.name)


async def test_agent_failure_without_report_closes_task_as_failed() -> None:
    capabilities = build_mock_capabilities()
    default_agents = build_agent_registry(capabilities).as_mapping()
    default_agents[AgentRoute.SOURCE_ANALYSIS.value] = FailingSourceAgent()
    default_agents[AgentRoute.REPORT.value] = EmptyReportAgent()
    registry = AgentRegistry()
    registry.register_many(default_agents)
    services = build_application(capabilities, agent_registry=registry)
    task = services.task_manager.create_task(
        Target(
            target_id="failure-target",
            path="safe-mock-fixture",
            target_type=TargetType.SOURCE,
        )
    )

    with pytest.raises(ModuleExecutionError, match="without a report"):
        await services.orchestrator.run(task.task_id)

    stored = services.task_manager.get_task(task.task_id)
    context = services.orchestrator.get_context(task.task_id)
    events = services.event_bus.list_by_task(task.task_id)
    assert stored is not None
    assert stored.status is TaskStatus.FAILED
    assert context is not None
    assert context.task.status is TaskStatus.FAILED
    assert not context.reports
    assert not services.orchestrator.is_running(task.task_id)
    assert EventType.TASK_FAILED in {event.event_type for event in events}
    assert EventType.REPORT_GENERATED not in {
        event.event_type for event in events
    }
    started_routes = [
        event.payload["route"]
        for event in events
        if event.event_type is EventType.AGENT_STARTED
    ]
    assert started_routes == [
        AgentRoute.PLANNER.value,
        AgentRoute.SOURCE_ANALYSIS.value,
        AgentRoute.REPORT.value,
    ]


async def test_agent_failure_with_successful_report_still_marks_task_failed() -> None:
    capabilities = build_mock_capabilities()
    default_agents = build_agent_registry(capabilities).as_mapping()
    default_agents[AgentRoute.SOURCE_ANALYSIS.value] = FailingSourceAgent()
    registry = AgentRegistry()
    registry.register_many(default_agents)
    services = build_application(capabilities, agent_registry=registry)
    task = services.task_manager.create_task(
        Target(
            target_id="reported-failure-target",
            path="safe-mock-fixture",
            target_type=TargetType.SOURCE,
        )
    )

    context = await services.orchestrator.run(task.task_id)

    stored = services.task_manager.get_task(task.task_id)
    events = services.event_bus.list_by_task(task.task_id)
    assert stored is not None
    assert stored.status is TaskStatus.FAILED
    assert context.task.status is TaskStatus.FAILED
    assert context.reports
    assert not services.orchestrator.is_running(task.task_id)
    event_types = {event.event_type for event in events}
    assert EventType.REPORT_GENERATED in event_types
    assert EventType.TASK_FAILED in event_types
    assert any(
        event.event_type is EventType.AGENT_FINISHED
        and event.payload.get("success") is False
        for event in events
    )
