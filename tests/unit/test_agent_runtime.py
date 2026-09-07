from typing import get_type_hints

import pytest

from vulnagent.agent_runtime import AgentRoute, AgentRouter, AgentRuntime, AgentSuite, RouteDecision, RuntimePolicy, RuntimeState, Supervisor, ToolEnabledAgent, ToolRegistry, ToolSpec
from vulnagent.agents import BinaryAnalysisAgent, FuzzAgent, PlannerAgent, ReportAgent, ReviewerAgent, SourceAuditAgent, VerificationAgent
from vulnagent.analyzers.binary.reverse import MockBinaryReverseAnalyzer
from vulnagent.analyzers.source.audit import MockSourceAuditor
from vulnagent.analyzers.source.parser import MockSourceParser
from vulnagent.contracts import AgentResult, AnalysisContext, EventType, FuzzRequest, ModuleExecutionError, SourceAnalysisResult, Target, TargetType, Task, VerificationContext, VerificationResult, VulnerabilityCandidate, VulnerabilityStatus
from vulnagent.fuzz.mock import MockFuzzEngine
from vulnagent.report.generator import MockReportGenerator
from vulnagent.verification.verifier import MockVerifier


class EmptySourceAuditor:
    async def audit(self, result: SourceAnalysisResult) -> list[VulnerabilityCandidate]:
        return []


class InvalidStatusAuditor:
    async def audit(self, result: SourceAnalysisResult) -> list[VulnerabilityCandidate]:
        return [
            VulnerabilityCandidate(
                vulnerability_id="invalid",
                task_id=result.task_id,
                title="invalid",
                vulnerability_type="invalid",
                description="Discovery attempted to bypass verification.",
                target_id=result.target_id,
                source_agent="source_audit",
                confidence=0.5,
                status=VulnerabilityStatus.CONFIRMED,
            )
        ]


class RetryVerifier:
    async def verify(self, candidate: VulnerabilityCandidate, context: VerificationContext) -> VerificationResult:
        return VerificationResult(
            vulnerability_id=candidate.vulnerability_id,
            task_id=candidate.task_id,
            status=VulnerabilityStatus.UNCERTAIN,
            confidence=candidate.confidence,
            rationale="More analysis requested by test verifier.",
            evidence_ids=[item.evidence_id for item in context.evidence],
            metadata={"request_additional_analysis": True},
        )


class StatusVerifier:
    def __init__(self, status: VulnerabilityStatus) -> None:
        self.status = status

    async def verify(self, candidate: VulnerabilityCandidate, context: VerificationContext) -> VerificationResult:
        return VerificationResult(
            vulnerability_id=candidate.vulnerability_id,
            task_id=candidate.task_id,
            status=self.status,
            confidence=candidate.confidence,
            rationale="Explicit verification boundary decision.",
            evidence_ids=[item.evidence_id for item in context.evidence],
        )


class LoopSupervisor(Supervisor):
    def decide(self, task: Task, context: AnalysisContext, state: RuntimeState) -> RouteDecision:
        return RouteDecision(AgentRoute.PLANNER, "repeat forever")


class InvalidSupervisor(Supervisor):
    def decide(self, task: Task, context: AnalysisContext, state: RuntimeState) -> RouteDecision:
        return RouteDecision("not-a-route", "invalid test route")  # type: ignore[arg-type]


class ExampleToolAgent(ToolEnabledAgent):
    name = "example"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        return AgentResult(agent_name=self.name)


def build_runtime(*, source_auditor=None, verifier=None, supervisor=None, policy=None, events=None) -> AgentRuntime:
    suite = AgentSuite(
        planner=PlannerAgent(),
        source_analysis=SourceAuditAgent(MockSourceParser(), source_auditor or MockSourceAuditor()),
        binary_analysis=BinaryAnalysisAgent(MockBinaryReverseAnalyzer()),
        fuzz=FuzzAgent(MockFuzzEngine()),
        verification=VerificationAgent(verifier or MockVerifier()),
        reviewer=ReviewerAgent(),
        report=ReportAgent(MockReportGenerator()),
    )
    publisher = events.append if events is not None else None
    return AgentRuntime(suite.as_mapping(), supervisor=supervisor, policy=policy, publish_event=publisher)


def make_task(target_type: TargetType = TargetType.SOURCE, metadata: dict | None = None) -> Task:
    return Task(task_id="task", target=Target(target_id="target", path="fixture", target_type=target_type, metadata=metadata or {}))


def test_runtime_state_has_only_typed_routing_fields() -> None:
    assert set(get_type_hints(RuntimeState)) == {
        "task_id", "current_agent", "next_agent", "step_count", "route_history", "messages",
        "pending_actions", "completed_agents", "runtime_metadata",
    }


def test_router_valid_invalid_fallback_and_finish() -> None:
    router = AgentRouter(RuntimePolicy(max_agent_steps=3, max_route_repeats=2))
    assert router.resolve("source_analysis", []).route is AgentRoute.SOURCE_ANALYSIS
    invalid = router.resolve("illegal", [])
    assert invalid.route is AgentRoute.REPORT and invalid.fallback_used
    assert router.resolve(AgentRoute.FINISH, []).route is AgentRoute.FINISH
    assert router.resolve(AgentRoute.SOURCE_ANALYSIS, ["source_analysis", "source_analysis"]).route is AgentRoute.REPORT
    assert router.resolve(AgentRoute.PLANNER, ["planner", "source_analysis", "verification"]).route is AgentRoute.REPORT


@pytest.mark.parametrize(
    ("target_type", "expected"),
    [(TargetType.SOURCE, "source_analysis"), (TargetType.PROJECT, "source_analysis"), (TargetType.BINARY, "binary_analysis")],
)
async def test_target_type_selects_analysis_route(target_type: TargetType, expected: str) -> None:
    task = make_task(target_type)
    result = await build_runtime().run(task, AnalysisContext(task=task))
    assert result.state["route_history"][:2] == ["planner", expected]
    assert "fuzz" not in result.state["route_history"]
    assert result.state["route_history"][-1] == "report"


async def test_zero_finding_routes_directly_to_report() -> None:
    task = make_task()
    result = await build_runtime(source_auditor=EmptySourceAuditor()).run(task, AnalysisContext(task=task))
    assert result.state["route_history"] == ["planner", "source_analysis", "report"]
    assert result.context.findings == []


async def test_fuzz_requires_authorization_and_planner_value() -> None:
    unauthorized = make_task(metadata={"dynamic_validation": True})
    unauthorized_result = await build_runtime().run(unauthorized, AnalysisContext(task=unauthorized))
    assert "fuzz" not in unauthorized_result.state["route_history"]

    authorized = make_task(metadata={"dynamic_validation": True, "fuzz_authorized": True})
    authorized_result = await build_runtime().run(authorized, AnalysisContext(task=authorized))
    assert "fuzz" in authorized_result.state["route_history"]
    fuzz_messages = [item for item in authorized_result.context.messages if item.message_type.value == "fuzz_result"]
    assert fuzz_messages and fuzz_messages[0].payload["executed"] is False


async def test_verification_additional_analysis_is_bounded() -> None:
    task = make_task()
    result = await build_runtime(verifier=RetryVerifier()).run(task, AnalysisContext(task=task))
    assert result.state["route_history"].count("source_analysis") == 2
    assert result.state["route_history"].count("verification") == 2
    assert result.state["route_history"][-2:] == ["reviewer", "report"]


async def test_agent_step_limit_forces_safe_report() -> None:
    task = make_task()
    policy = RuntimePolicy(max_agent_steps=3, max_route_repeats=100)
    result = await build_runtime(supervisor=LoopSupervisor(), policy=policy).run(task, AnalysisContext(task=task))
    assert result.step_limit_reached
    assert result.state["route_history"] == ["planner", "planner", "planner", "report"]
    assert result.context.reports


async def test_invalid_supervisor_route_does_not_crash() -> None:
    task = make_task()
    result = await build_runtime(supervisor=InvalidSupervisor()).run(task, AnalysisContext(task=task))
    assert result.state["route_history"] == ["report"]
    assert result.state["runtime_metadata"]["fallback_used"] is True


async def test_discovery_is_candidate_and_evidence_first() -> None:
    task = make_task()
    result = await build_runtime().run(task, AnalysisContext(task=task))
    candidate_message = next(item for item in result.context.messages if item.message_type.value == "vulnerability_candidate")
    verification_index = result.state["route_history"].index("verification")
    assert candidate_message.evidence_ids
    assert result.context.findings[0].evidence_ids
    assert verification_index > result.state["route_history"].index("source_analysis")


async def test_runtime_rejects_final_status_from_discovery() -> None:
    task = make_task()
    with pytest.raises(ModuleExecutionError, match="Discovery agent cannot emit final status"):
        await build_runtime(source_auditor=InvalidStatusAuditor()).run(task, AnalysisContext(task=task))


@pytest.mark.parametrize(
    "status",
    [VulnerabilityStatus.CONFIRMED, VulnerabilityStatus.REJECTED, VulnerabilityStatus.UNCERTAIN],
)
async def test_only_verification_agent_applies_final_status(status: VulnerabilityStatus) -> None:
    task = make_task()
    result = await build_runtime(verifier=StatusVerifier(status)).run(task, AnalysisContext(task=task))
    assert result.context.findings
    assert {item.status for item in result.context.findings} == {status}
    assert {item.status for item in result.context.verifications} == {status}


async def test_runtime_trace_uses_messages_and_domain_events() -> None:
    events = []
    task = make_task()
    result = await build_runtime(events=events).run(task, AnalysisContext(task=task))
    assert result.state["messages"] == result.context.messages
    event_types = {item.event_type for item in events}
    assert EventType.AGENT_ROUTED in event_types
    assert EventType.AGENT_STARTED in event_types
    assert EventType.REVIEW_COMPLETED in event_types
    assert EventType.REPORT_GENERATED in event_types


async def test_tool_registry_exposes_logical_capabilities() -> None:
    async def adapter(value: int) -> int:
        return value + 1

    registry = ToolRegistry()
    registry.register(ToolSpec("source.parse", "parse", adapter, "P2", "source"))
    assert await registry.get("source.parse").adapter(1) == 2
    assert [item.name for item in registry.list_tools()] == ["source.parse"]
    agent = ExampleToolAgent(registry, ["source.parse"])
    assert agent.tool_names == ("source.parse",)
    assert await agent.invoke_tool("source.parse", 2) == 3
    with pytest.raises(PermissionError):
        await agent.invoke_tool("binary.inspect", 2)


async def test_unauthorized_mock_fuzz_never_executes() -> None:
    result = await MockFuzzEngine().run(FuzzRequest(task_id="task", target_id="target", target_path="fixture", authorized=False))
    assert result.executed is False
