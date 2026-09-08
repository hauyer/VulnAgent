from typing import get_type_hints

import pytest

from vulnagent.agent_runtime import (
    AgentRoute,
    AgentRouter,
    AgentRuntime,
    AgentSuite,
    RouteDecision,
    RuntimePolicy,
    RuntimeState,
    Supervisor,
    ToolEnabledAgent,
    ToolRegistry,
    ToolSpec,
)
from vulnagent.agents import (
    BinaryAnalysisAgent,
    FuzzAgent,
    PlannerAgent,
    ReportAgent,
    ReviewerAgent,
    SourceAuditAgent,
    VerificationAgent,
)
from vulnagent.analyzers.binary.reverse import (
    MockBinaryReverseAnalyzer,
)
from vulnagent.analyzers.source.audit import (
    MockSourceAuditor,
)
from vulnagent.analyzers.source.parser import (
    MockSourceParser,
)
from vulnagent.contracts import (
    AgentResult,
    AnalysisContext,
    EventType,
    FuzzRequest,
    SourceAnalysisResult,
    Target,
    TargetType,
    Task,
    VerificationContext,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityStatus,
)
from vulnagent.fuzz.mock import MockFuzzEngine
from vulnagent.report.generator import MockReportGenerator
from vulnagent.verification.verifier import MockVerifier


# ============================================================
# Test doubles
# ============================================================


class EmptySourceAuditor:
    """Source auditor returning no vulnerabilities."""

    async def audit(
        self,
        result: SourceAnalysisResult,
    ) -> list[VulnerabilityCandidate]:
        return []


class InvalidStatusAuditor:
    """Malicious/invalid discovery implementation.

    Discovery agents are not allowed to directly emit a final
    vulnerability status such as CONFIRMED.
    """

    async def audit(
        self,
        result: SourceAnalysisResult,
    ) -> list[VulnerabilityCandidate]:
        return [
            VulnerabilityCandidate(
                vulnerability_id="invalid",
                task_id=result.task_id,
                title="invalid",
                vulnerability_type="invalid",
                description=(
                    "Discovery attempted to bypass verification."
                ),
                target_id=result.target_id,
                source_agent="source_audit",
                confidence=0.5,
                status=VulnerabilityStatus.CONFIRMED,
            )
        ]


class ExplodingSourceAuditor:
    """Auditor used to verify runtime exception fallback."""

    async def audit(
        self,
        result: SourceAnalysisResult,
    ) -> list[VulnerabilityCandidate]:
        raise RuntimeError(
            "source auditor boom"
        )


class RetryVerifier:
    """Verifier that always requests one more analysis pass."""

    async def verify(
        self,
        candidate: VulnerabilityCandidate,
        context: VerificationContext,
    ) -> VerificationResult:
        return VerificationResult(
            vulnerability_id=candidate.vulnerability_id,
            task_id=candidate.task_id,
            status=VulnerabilityStatus.UNCERTAIN,
            confidence=candidate.confidence,
            rationale=(
                "More analysis requested by test verifier."
            ),
            evidence_ids=[
                item.evidence_id
                for item in context.evidence
            ],
            metadata={
                "request_additional_analysis": True,
            },
        )


class StatusVerifier:
    """Verifier returning one explicitly configured final status."""

    def __init__(
        self,
        status: VulnerabilityStatus,
    ) -> None:
        self.status = status

    async def verify(
        self,
        candidate: VulnerabilityCandidate,
        context: VerificationContext,
    ) -> VerificationResult:
        return VerificationResult(
            vulnerability_id=candidate.vulnerability_id,
            task_id=candidate.task_id,
            status=self.status,
            confidence=candidate.confidence,
            rationale=(
                "Explicit verification boundary decision."
            ),
            evidence_ids=[
                item.evidence_id
                for item in context.evidence
            ],
        )


class LoopSupervisor(Supervisor):
    """Supervisor that tries to route to planner forever."""

    def decide(
        self,
        task: Task,
        context: AnalysisContext,
        state: RuntimeState,
    ) -> RouteDecision:
        return RouteDecision(
            AgentRoute.PLANNER,
            "repeat forever",
        )


class InvalidSupervisor(Supervisor):
    """Supervisor returning an illegal AgentRoute value."""

    def decide(
        self,
        task: Task,
        context: AnalysisContext,
        state: RuntimeState,
    ) -> RouteDecision:
        return RouteDecision(
            "not-a-route",  # type: ignore[arg-type]
            "invalid test route",
        )


class ExplodingSupervisor(Supervisor):
    """Supervisor throwing an unexpected runtime exception."""

    def decide(
        self,
        task: Task,
        context: AnalysisContext,
        state: RuntimeState,
    ) -> RouteDecision:
        raise RuntimeError(
            "supervisor boom"
        )


class ExampleToolAgent(ToolEnabledAgent):
    """Minimal ToolEnabledAgent used for ToolRegistry tests."""

    name = "example"

    async def run(
        self,
        task: Task,
        context: AnalysisContext,
    ) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
        )


# ============================================================
# Runtime builders
# ============================================================


def build_runtime(
    *,
    source_auditor=None,
    verifier=None,
    supervisor=None,
    policy=None,
    events=None,
) -> AgentRuntime:
    """Create one fully injected mock AgentRuntime."""

    suite = AgentSuite(
        planner=PlannerAgent(),
        source_analysis=SourceAuditAgent(
            MockSourceParser(),
            source_auditor or MockSourceAuditor(),
        ),
        binary_analysis=BinaryAnalysisAgent(
            MockBinaryReverseAnalyzer()
        ),
        fuzz=FuzzAgent(
            MockFuzzEngine()
        ),
        verification=VerificationAgent(
            verifier or MockVerifier()
        ),
        reviewer=ReviewerAgent(),
        report=ReportAgent(
            MockReportGenerator()
        ),
    )

    publisher = (
        events.append
        if events is not None
        else None
    )

    return AgentRuntime(
        suite.as_mapping(),
        supervisor=supervisor,
        policy=policy,
        publish_event=publisher,
    )


def make_task(
    target_type: TargetType = TargetType.SOURCE,
    metadata: dict | None = None,
) -> Task:
    """Create a minimal runtime task."""

    return Task(
        task_id="task",
        target=Target(
            target_id="target",
            path="fixture",
            target_type=target_type,
            metadata=metadata or {},
        ),
    )


# ============================================================
# RuntimeState tests
# ============================================================


def test_runtime_state_has_only_typed_routing_fields() -> None:
    """RuntimeState must not duplicate business context."""

    assert set(
        get_type_hints(RuntimeState)
    ) == {
        "task_id",
        "current_agent",
        "next_agent",
        "step_count",
        "route_history",
        "messages",
        "pending_actions",
        "completed_agents",
        "runtime_metadata",
    }


# ============================================================
# RuntimePolicy tests
# ============================================================


def test_runtime_policy_defaults() -> None:
    """V0.2 bounded runtime defaults must remain stable."""

    policy = RuntimePolicy()

    assert policy.max_agent_steps == 15
    assert policy.max_route_repeats == 2
    assert policy.max_analysis_retries == 1


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {
                "max_agent_steps": 0,
            },
            "max_agent_steps must be positive",
        ),
        (
            {
                "max_route_repeats": 0,
            },
            "max_route_repeats must be positive",
        ),
        (
            {
                "max_analysis_retries": -1,
            },
            "max_analysis_retries cannot be negative",
        ),
    ],
)
def test_runtime_policy_rejects_invalid_bounds(
    kwargs: dict,
    message: str,
) -> None:
    """Invalid runtime bounds must fail during construction."""

    with pytest.raises(
        ValueError,
        match=message,
    ):
        RuntimePolicy(
            **kwargs
        )


# ============================================================
# AgentRouter tests
# ============================================================


def test_router_accepts_valid_route() -> None:
    """Legal routes pass through the Router."""

    router = AgentRouter(
        RuntimePolicy(
            max_agent_steps=5,
            max_route_repeats=2,
        )
    )

    decision = router.resolve(
        AgentRoute.SOURCE_ANALYSIS,
        [],
    )

    assert (
        decision.route
        is AgentRoute.SOURCE_ANALYSIS
    )

    assert (
        decision.fallback_used
        is False
    )


def test_router_rejects_invalid_route() -> None:
    """Unknown supervisor output must never enter the graph."""

    router = AgentRouter()

    decision = router.resolve(
        "illegal-agent-route",
        [],
    )

    assert (
        decision.route
        is AgentRoute.REPORT
    )

    assert (
        decision.fallback_used
        is True
    )

    assert (
        "invalid supervisor route"
        in decision.reason
    )


def test_router_invalid_route_after_report_finishes() -> None:
    """If report already executed, fallback must terminate."""

    router = AgentRouter()

    decision = router.resolve(
        "illegal-agent-route",
        [
            AgentRoute.REPORT.value,
        ],
    )

    assert (
        decision.route
        is AgentRoute.FINISH
    )

    assert (
        decision.fallback_used
        is True
    )


def test_router_allows_finish() -> None:
    """FINISH is always a legal non-executable destination."""

    router = AgentRouter()

    decision = router.resolve(
        AgentRoute.FINISH,
        [],
    )

    assert (
        decision.route
        is AgentRoute.FINISH
    )

    assert (
        decision.fallback_used
        is False
    )


def test_router_rejects_route_after_repeat_limit() -> None:
    """A route cannot execute more than max_route_repeats."""

    router = AgentRouter(
        RuntimePolicy(
            max_agent_steps=10,
            max_route_repeats=2,
        )
    )

    decision = router.resolve(
        AgentRoute.SOURCE_ANALYSIS,
        [
            "source_analysis",
            "source_analysis",
        ],
    )

    assert (
        decision.route
        is AgentRoute.REPORT
    )

    assert (
        decision.fallback_used
        is True
    )

    assert (
        "route repeat limit"
        in decision.reason
    )


def test_router_never_executes_agent_beyond_step_limit() -> None:
    """A fully exhausted Agent budget must terminate."""

    router = AgentRouter(
        RuntimePolicy(
            max_agent_steps=3,
            max_route_repeats=100,
        )
    )

    decision = router.resolve(
        AgentRoute.PLANNER,
        [
            "planner",
            "source_analysis",
            "verification",
        ],
    )

    assert (
        decision.route
        is AgentRoute.FINISH
    )

    assert (
        decision.fallback_used
        is True
    )

    assert (
        "step limit"
        in decision.reason
    )


def test_router_reserves_last_step_for_report() -> None:
    """The final executable slot should be reserved for Report."""

    router = AgentRouter(
        RuntimePolicy(
            max_agent_steps=3,
            max_route_repeats=100,
        )
    )

    decision = router.resolve(
        AgentRoute.PLANNER,
        [
            "planner",
            "planner",
        ],
    )

    assert (
        decision.route
        is AgentRoute.REPORT
    )

    assert (
        decision.fallback_used
        is True
    )

    assert (
        "step limit"
        in decision.reason
    )


# ============================================================
# Normal routing tests
# ============================================================


@pytest.mark.parametrize(
    (
        "target_type",
        "expected",
    ),
    [
        (
            TargetType.SOURCE,
            "source_analysis",
        ),
        (
            TargetType.PROJECT,
            "source_analysis",
        ),
        (
            TargetType.BINARY,
            "binary_analysis",
        ),
    ],
)
async def test_target_type_selects_analysis_route(
    target_type: TargetType,
    expected: str,
) -> None:
    """Planner must select source/binary analysis by target type."""

    task = make_task(
        target_type
    )

    result = await build_runtime().run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.state[
            "route_history"
        ][:2]
        == [
            "planner",
            expected,
        ]
    )

    assert (
        "fuzz"
        not in result.state[
            "route_history"
        ]
    )

    assert (
        result.state[
            "route_history"
        ][-1]
        == "report"
    )


async def test_zero_finding_routes_directly_to_report() -> None:
    """No findings should skip verification/reviewer."""

    task = make_task()

    result = await build_runtime(
        source_auditor=
            EmptySourceAuditor()
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.state[
            "route_history"
        ]
        == [
            "planner",
            "source_analysis",
            "report",
        ]
    )

    assert (
        result.context.findings
        == []
    )


# ============================================================
# Fuzz routing tests
# ============================================================


async def test_fuzz_requires_authorization_and_planner_value() -> None:
    """Dynamic execution requires explicit authorization and plan."""

    unauthorized = make_task(
        metadata={
            "dynamic_validation": True,
        }
    )

    unauthorized_result = (
        await build_runtime().run(
            unauthorized,
            AnalysisContext(
                task=unauthorized
            ),
        )
    )

    assert (
        "fuzz"
        not in unauthorized_result.state[
            "route_history"
        ]
    )

    authorized = make_task(
        metadata={
            "dynamic_validation": True,
            "fuzz_authorized": True,
        }
    )

    authorized_result = (
        await build_runtime().run(
            authorized,
            AnalysisContext(
                task=authorized
            ),
        )
    )

    assert (
        "fuzz"
        in authorized_result.state[
            "route_history"
        ]
    )

    fuzz_messages = [
        item
        for item
        in authorized_result.context.messages
        if item.message_type.value
        == "fuzz_result"
    ]

    assert fuzz_messages

    assert (
        fuzz_messages[0]
        .payload["executed"]
        is False
    )


async def test_unauthorized_mock_fuzz_never_executes() -> None:
    """Mock fuzz engine must respect the authorization boundary."""

    result = await MockFuzzEngine().run(
        FuzzRequest(
            task_id="task",
            target_id="target",
            target_path="fixture",
            authorized=False,
        )
    )

    assert (
        result.executed
        is False
    )


# ============================================================
# Analysis retry tests
# ============================================================


async def test_verification_additional_analysis_is_bounded() -> None:
    """Default policy permits exactly one additional analysis pass."""

    task = make_task()

    result = await build_runtime(
        verifier=RetryVerifier()
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.state[
            "route_history"
        ].count(
            "source_analysis"
        )
        == 2
    )

    assert (
        result.state[
            "route_history"
        ].count(
            "verification"
        )
        == 2
    )

    assert (
        result.state[
            "route_history"
        ][-2:]
        == [
            "reviewer",
            "report",
        ]
    )

    assert (
        result.state[
            "runtime_metadata"
        ].get(
            "analysis_retries",
            0,
        )
        == 1
    )


async def test_analysis_retry_can_be_disabled_by_policy() -> None:
    """max_analysis_retries=0 must disable additional analysis."""

    task = make_task()

    policy = RuntimePolicy(
        max_analysis_retries=0,
    )

    result = await build_runtime(
        verifier=RetryVerifier(),
        policy=policy,
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.state[
            "route_history"
        ].count(
            "source_analysis"
        )
        == 1
    )

    assert (
        result.state[
            "route_history"
        ].count(
            "verification"
        )
        == 1
    )

    assert (
        result.state[
            "runtime_metadata"
        ].get(
            "analysis_retries",
            0,
        )
        == 0
    )

    assert (
        "reviewer"
        in result.state[
            "route_history"
        ]
    )


async def test_analysis_retry_counter_matches_actual_retry_events() -> None:
    """Retry metadata and AGENT_RETRY events must agree."""

    events = []

    task = make_task()

    result = await build_runtime(
        verifier=RetryVerifier(),
        events=events,
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    retry_events = [
        event
        for event in events
        if event.event_type
        is EventType.AGENT_RETRY
    ]

    assert (
        len(retry_events)
        == 1
    )

    assert (
        result.state[
            "runtime_metadata"
        ]["analysis_retries"]
        == 1
    )

    assert (
        retry_events[0]
        .payload["attempt"]
        == 1
    )

    assert (
        retry_events[0]
        .payload["max_attempts"]
        == 1
    )


# ============================================================
# Step limit and repeat-limit integration tests
# ============================================================


async def test_agent_step_limit_is_hard_bound_and_forces_safe_report() -> None:
    """Actual Agent executions must never exceed max_agent_steps."""

    task = make_task()

    policy = RuntimePolicy(
        max_agent_steps=3,
        max_route_repeats=100,
    )

    result = await build_runtime(
        supervisor=LoopSupervisor(),
        policy=policy,
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.step_limit_reached
        is True
    )

    assert (
        result.state[
            "route_history"
        ]
        == [
            "planner",
            "planner",
            "report",
        ]
    )

    assert (
        result.state[
            "step_count"
        ]
        == len(
            result.state[
                "route_history"
            ]
        )
        == 3
    )

    assert (
        result.state[
            "step_count"
        ]
        <= policy.max_agent_steps
    )

    assert (
        result.context.reports
    )


async def test_route_repeat_limit_falls_back_after_exact_bound() -> None:
    """Third request for same route must not execute."""

    task = make_task()

    policy = RuntimePolicy(
        max_agent_steps=10,
        max_route_repeats=2,
    )

    result = await build_runtime(
        supervisor=LoopSupervisor(),
        policy=policy,
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.state[
            "route_history"
        ].count(
            "planner"
        )
        == 2
    )

    assert (
        result.state[
            "route_history"
        ][-1]
        == "report"
    )

    assert (
        result.state[
            "runtime_metadata"
        ]["fallback_used"]
        is True
    )

    assert (
        "route repeat limit"
        in result.termination_reason
    )


# ============================================================
# Invalid route tests
# ============================================================


async def test_invalid_supervisor_route_does_not_crash() -> None:
    """An invalid AgentRoute should safely fall back to Report."""

    task = make_task()

    result = await build_runtime(
        supervisor=InvalidSupervisor()
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.state[
            "route_history"
        ]
        == [
            "report",
        ]
    )

    assert (
        result.context.reports
    )

    assert (
        result.state[
            "runtime_metadata"
        ]["fallback_used"]
        is True
    )

    assert (
        "invalid supervisor route"
        in result.termination_reason
    )


# ============================================================
# Supervisor exception fallback tests
# ============================================================


async def test_supervisor_exception_falls_back_to_report() -> None:
    """Unexpected supervisor failure must not crash LangGraph."""

    task = make_task()

    result = await build_runtime(
        supervisor=ExplodingSupervisor()
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.state[
            "route_history"
        ]
        == [
            "report",
        ]
    )

    assert (
        result.context.reports
    )

    assert (
        result.state[
            "runtime_metadata"
        ]["fallback_used"]
        is True
    )

    assert (
        "supervisor execution failed"
        in result.termination_reason
    )


# ============================================================
# Agent exception fallback tests
# ============================================================


async def test_agent_exception_falls_back_to_report_with_trace() -> None:
    """Agent failure should produce ERROR trace and safe Report fallback."""

    task = make_task()

    result = await build_runtime(
        source_auditor=
            ExplodingSourceAuditor()
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.state[
            "route_history"
        ]
        == [
            "planner",
            "source_analysis",
            "report",
        ]
    )

    assert (
        result.context.reports
    )

    error_messages = [
        message
        for message
        in result.context.messages
        if message.message_type.value
        == "error"
    ]

    assert error_messages

    last_error = (
        error_messages[-1]
    )

    assert (
        last_error.payload[
            "route"
        ]
        == "source_analysis"
    )

    assert (
        "source auditor boom"
        in last_error.payload[
            "error"
        ]
    )

    metadata = result.state[
        "runtime_metadata"
    ]

    assert (
        metadata[
            "fallback_used"
        ]
        is True
    )

    assert (
        metadata[
            "last_agent_error"
        ]["route"]
        == "source_analysis"
    )

    assert (
        metadata[
            "last_agent_error"
        ]["agent"]
        == "source_audit"
    )

    assert (
        "source auditor boom"
        in metadata[
            "last_agent_error"
        ]["error"]
    )

    assert (
        result.state[
            "messages"
        ]
        == result.context.messages
    )

    assert (
        result.state[
            "step_count"
        ]
        == len(
            result.state[
                "route_history"
            ]
        )
    )

    assert (
        "agent execution failed"
        in result.termination_reason
    )


# ============================================================
# Finding authority tests
# ============================================================


async def test_discovery_is_candidate_and_evidence_first() -> None:
    """Discovery output must remain candidate + evidence backed."""

    task = make_task()

    result = await build_runtime().run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    candidate_message = next(
        item
        for item
        in result.context.messages
        if item.message_type.value
        == "vulnerability_candidate"
    )

    verification_index = (
        result.state[
            "route_history"
        ].index(
            "verification"
        )
    )

    assert (
        candidate_message.evidence_ids
    )

    assert (
        result.context.findings[
            0
        ].evidence_ids
    )

    assert (
        verification_index
        > result.state[
            "route_history"
        ].index(
            "source_analysis"
        )
    )


async def test_runtime_rejects_final_status_from_discovery() -> None:
    """Discovery cannot bypass the Verification authority boundary."""

    task = make_task()

    result = await build_runtime(
        source_auditor=
            InvalidStatusAuditor()
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    # Illegal finding must never be merged into AnalysisContext.
    assert all(
        finding.vulnerability_id
        != "invalid"
        for finding
        in result.context.findings
    )

    assert (
        result.state[
            "route_history"
        ]
        == [
            "planner",
            "source_analysis",
            "report",
        ]
    )

    assert (
        result.context.reports
    )

    error_messages = [
        message
        for message
        in result.context.messages
        if message.message_type.value
        == "error"
    ]

    assert error_messages

    assert (
        "Discovery agent cannot emit final status"
        in error_messages[-1]
        .payload["error"]
    )


@pytest.mark.parametrize(
    "status",
    [
        VulnerabilityStatus.CONFIRMED,
        VulnerabilityStatus.REJECTED,
        VulnerabilityStatus.UNCERTAIN,
    ],
)
async def test_only_verification_agent_applies_final_status(
    status: VulnerabilityStatus,
) -> None:
    """Only Verification may write final vulnerability states."""

    task = make_task()

    result = await build_runtime(
        verifier=StatusVerifier(
            status
        )
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.context.findings
    )

    assert {
        item.status
        for item
        in result.context.findings
    } == {
        status
    }

    assert {
        item.status
        for item
        in result.context.verifications
    } == {
        status
    }


# ============================================================
# Runtime trace tests
# ============================================================


async def test_runtime_trace_uses_messages_and_domain_events() -> None:
    """Trace should use structured messages/events rather than hidden reasoning."""

    events = []

    task = make_task()

    result = await build_runtime(
        events=events
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.state[
            "messages"
        ]
        == result.context.messages
    )

    event_types = {
        item.event_type
        for item in events
    }

    assert (
        EventType.AGENT_ROUTED
        in event_types
    )

    assert (
        EventType.AGENT_STARTED
        in event_types
    )

    assert (
        EventType.AGENT_FINISHED
        in event_types
    )

    assert (
        EventType.REVIEW_COMPLETED
        in event_types
    )

    assert (
        EventType.REPORT_GENERATED
        in event_types
    )


async def test_exception_trace_contains_failed_agent_event() -> None:
    """Agent failure must remain observable through DomainEvent trace."""

    events = []

    task = make_task()

    result = await build_runtime(
        source_auditor=
            ExplodingSourceAuditor(),
        events=events,
    ).run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    failed_events = [
        event
        for event in events
        if (
            event.event_type
            is EventType.AGENT_FINISHED
            and event.payload.get(
                "success"
            )
            is False
        )
    ]

    assert failed_events

    failed = failed_events[-1]

    assert (
        failed.payload[
            "route"
        ]
        == "source_analysis"
    )

    assert (
        "source auditor boom"
        in failed.payload[
            "error"
        ]
    )

    assert (
        result.context.reports
    )


async def test_runtime_step_count_matches_route_history() -> None:
    """step_count and route_history must describe the same executions."""

    task = make_task()

    result = await build_runtime().run(
        task,
        AnalysisContext(
            task=task
        ),
    )

    assert (
        result.state[
            "step_count"
        ]
        == len(
            result.state[
                "route_history"
            ]
        )
    )


# ============================================================
# ToolRegistry tests
# ============================================================


async def test_tool_registry_exposes_logical_capabilities() -> None:
    """Agents should consume logical capability names."""

    async def adapter(
        value: int,
    ) -> int:
        return value + 1

    registry = ToolRegistry()

    registry.register(
        ToolSpec(
            "source.parse",
            "parse",
            adapter,
            "P2",
            "source",
        )
    )

    tool = registry.get(
        "source.parse"
    )

    assert (
        await tool.adapter(
            1
        )
        == 2
    )

    assert [
        item.name
        for item
        in registry.list_tools()
    ] == [
        "source.parse"
    ]

    agent = ExampleToolAgent(
        registry,
        [
            "source.parse",
        ],
    )

    assert (
        agent.tool_names
        == (
            "source.parse",
        )
    )

    assert (
        await agent.invoke_tool(
            "source.parse",
            2,
        )
        == 3
    )

    with pytest.raises(
        PermissionError
    ):
        await agent.invoke_tool(
            "binary.inspect",
            2,
        )