"""LangGraph-backed execution of the bounded VulnAgent agent workflow."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from langgraph.graph import END, START, StateGraph

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import (
    AgentMessage,
    AgentMessageType,
    AnalysisContext,
    DomainEvent,
    EventType,
    ModuleExecutionError,
    Task,
    TaskStatus,
)
from vulnagent.core.pipeline import Pipeline, PipelineStage
from vulnagent.core.trace_safety import ensure_public_trace_payload
from vulnagent.llm.base import BaseLLM
from vulnagent.utils.ids import new_message_id

from .policies import RuntimePolicy
from .router import AgentRoute, AgentRouter, RouteDecision
from .state import RuntimeState, initial_runtime_state
from .supervisor import Supervisor
from .tool_registry import ToolRegistry

EventPublisher = Callable[[DomainEvent], None]
RouteObserver = Callable[[AgentRoute], None]


@dataclass(frozen=True, slots=True)
class RuntimeResult:
    """Structured outcome of one agent graph invocation."""

    state: RuntimeState
    context: AnalysisContext
    termination_reason: str
    step_limit_reached: bool = False


@dataclass(frozen=True, slots=True)
class AgentSuite:
    """Injected agents available to the V0.2 runtime."""

    planner: BaseAgent
    source_analysis: BaseAgent
    binary_analysis: BaseAgent
    fuzz: BaseAgent
    verification: BaseAgent
    reviewer: BaseAgent
    report: BaseAgent

    def as_mapping(self) -> dict[str, BaseAgent]:
        """Return graph route names mapped to their replaceable agent."""
        return {
            AgentRoute.PLANNER.value: self.planner,
            AgentRoute.SOURCE_ANALYSIS.value: self.source_analysis,
            AgentRoute.BINARY_ANALYSIS.value: self.binary_analysis,
            AgentRoute.FUZZ.value: self.fuzz,
            AgentRoute.VERIFICATION.value: self.verification,
            AgentRoute.REVIEWER.value: self.reviewer,
            AgentRoute.REPORT.value: self.report,
        }


class AgentRuntime:
    """Build and execute a dynamic graph over injected ``BaseAgent`` objects."""

    def __init__(
        self,
        agents: Mapping[str, BaseAgent],
        *,
        supervisor: Supervisor | None = None,
        router: AgentRouter | None = None,
        policy: RuntimePolicy | None = None,
        pipeline: Pipeline | None = None,
        publish_event: EventPublisher | None = None,
        tool_registry: ToolRegistry | None = None,
        llm: BaseLLM | None = None,
    ) -> None:
        self.policy = policy or RuntimePolicy()
        self.router = router or AgentRouter(self.policy)
        self.supervisor = supervisor or Supervisor(self.policy.max_analysis_retries)
        self.pipeline = pipeline or Pipeline()
        self.publish_event = publish_event
        self.tool_registry = tool_registry or ToolRegistry()
        self.llm = llm
        self._agents = dict(agents)
        required = {route.value for route in AgentRoute if route is not AgentRoute.FINISH}
        missing = required.difference(self._agents)
        if missing:
            raise ValueError(f"Missing runtime agents: {sorted(missing)}")

    async def run(
        self,
        task: Task,
        context: AnalysisContext,
        *,
        on_route: RouteObserver | None = None,
    ) -> RuntimeResult:
        """Execute the graph until finish or a safe bounded fallback."""
        graph = self._build_graph(task, context, on_route)
        final = await graph.ainvoke(
            initial_runtime_state(task.task_id),
            config={"recursion_limit": self.policy.max_agent_steps * 3 + 10},
        )
        state = RuntimeState(**final)
        step_limit = bool(state["runtime_metadata"].get("step_limit_reached", False))
        reason = str(state["runtime_metadata"].get("termination_reason", "workflow complete"))
        return RuntimeResult(state=state, context=context, termination_reason=reason, step_limit_reached=step_limit)

    def _build_graph(self, task: Task, context: AnalysisContext, on_route: RouteObserver | None):
        builder = StateGraph(RuntimeState)

        async def supervise(
            state: RuntimeState,
        ) -> RuntimeState:
            metadata = dict(state["runtime_metadata"])

            # -------------------------------------------------
            # 1. Agent failure can force the next route
            # -------------------------------------------------

            forced_reason = metadata.pop(
                "force_fallback_reason",
                None,
            )

            if forced_reason is not None:
                fallback_route = (
                    AgentRoute.FINISH
                    if AgentRoute.REPORT.value
                    in state["route_history"]
                    else AgentRoute.REPORT
                )

                proposed = RouteDecision(
                    route=fallback_route,
                    reason=str(forced_reason),
                    fallback_used=True,
                )

            else:
                # ---------------------------------------------
                # 2. Supervisor itself must not crash runtime
                # ---------------------------------------------

                try:
                    proposed = self.supervisor.decide(
                        task,
                        context,
                        state,
                    )

                except Exception as exc:
                    fallback_route = (
                        AgentRoute.FINISH
                        if AgentRoute.REPORT.value
                        in state["route_history"]
                        else AgentRoute.REPORT
                    )

                    proposed = RouteDecision(
                        route=fallback_route,
                        reason=(
                            "supervisor execution failed: "
                            f"{type(exc).__name__}"
                        ),
                        fallback_used=True,
                    )

            try:
                proposed = self._public_route_decision(proposed)
            except ValueError:
                fallback_route = (
                    AgentRoute.FINISH
                    if AgentRoute.REPORT.value
                    in state["route_history"]
                    else AgentRoute.REPORT
                )
                proposed = RouteDecision(
                    route=fallback_route,
                    reason="supervisor supplied non-public route metadata",
                    fallback_used=True,
                )

            # -------------------------------------------------
            # 3. Runtime independently enforces retry policy
            # -------------------------------------------------

            retry_requested = bool(
                proposed.metadata.get(
                    "retry",
                    False,
                )
            )

            retry_route = proposed.route in {
                AgentRoute.SOURCE_ANALYSIS,
                AgentRoute.BINARY_ANALYSIS,
            }

            retry_from_verification = (
                state["current_agent"]
                == AgentRoute.VERIFICATION.value
            )

            actual_retry_request = (
                retry_requested
                and retry_route
                and retry_from_verification
            )

            retry_attempts = int(
                metadata.get(
                    "analysis_retries",
                    0,
                )
            )

            # Even a custom/injected Supervisor cannot exceed
            # RuntimePolicy.max_analysis_retries.
            if (
                actual_retry_request
                and retry_attempts
                >= self.policy.max_analysis_retries
            ):
                proposed = RouteDecision(
                    route=AgentRoute.REVIEWER,
                    reason=(
                        "runtime analysis retry limit reached; "
                        "continue to reviewer"
                    ),
                    metadata={
                        "retry_exhausted": True,
                    },
                )

                actual_retry_request = False

            # -------------------------------------------------
            # 4. Router is the final route authority
            # -------------------------------------------------

            routed = self.router.resolve(
                proposed.route,
                state["route_history"],
            )

            # When Router accepts the proposed route, retain
            # Supervisor's semantic reason instead of replacing
            # it with the generic "validated supervisor route".
            if (
                routed.route == proposed.route
                and not routed.fallback_used
            ):
                decision = RouteDecision(
                    route=routed.route,
                    reason=proposed.reason,
                    fallback_used=proposed.fallback_used,
                    metadata=dict(proposed.metadata),
                )
            else:
                decision = routed

            # -------------------------------------------------
            # 5. Count retry only after Router accepted it
            # -------------------------------------------------

            retry_executed = (
                actual_retry_request
                and decision.route == proposed.route
                and not decision.fallback_used
            )

            if retry_executed:
                retry_attempts += 1

                metadata[
                    "analysis_retries"
                ] = retry_attempts

                self._emit(
                    EventType.AGENT_RETRY,
                    task.task_id,
                    "supervisor",
                    {
                        "route": decision.route.value,
                        "attempt": retry_attempts,
                        "max_attempts":
                            self.policy.max_analysis_retries,
                    },
                )

            if proposed.metadata.get(
                "retry_exhausted",
                False,
            ):
                metadata[
                    "analysis_retry_exhausted"
                ] = True

            # -------------------------------------------------
            # 6. Record fallback / termination information
            # -------------------------------------------------

            if decision.fallback_used:
                metadata["fallback_used"] = True
                metadata[
                    "termination_reason"
                ] = decision.reason

                if "step limit" in decision.reason:
                    metadata[
                        "step_limit_reached"
                    ] = True

            # -------------------------------------------------
            # 7. Structured route trace
            # -------------------------------------------------

            self._emit(
                EventType.AGENT_ROUTED,
                task.task_id,
                "supervisor",
                {
                    "route": decision.route.value,
                    "reason": decision.reason,
                    "fallback_used":
                        decision.fallback_used,
                },
            )

            return {
                **state,
                "next_agent":
                    decision.route.value,
                "runtime_metadata":
                    metadata,
            }

        builder.add_node("supervisor", supervise)
        for route in AgentRoute:
            if route is AgentRoute.FINISH:
                continue
            builder.add_node(route.value, self._agent_node(route, task, context, on_route))
            builder.add_edge(route.value, "supervisor")

        builder.add_edge(START, "supervisor")
        builder.add_conditional_edges(
            "supervisor",
            lambda state: state["next_agent"],
            {**{route.value: route.value for route in AgentRoute if route is not AgentRoute.FINISH}, AgentRoute.FINISH.value: END},
        )
        return builder.compile()

    def _agent_node(
        self,
        route: AgentRoute,
        task: Task,
        context: AnalysisContext,
        on_route: RouteObserver | None,
    ):
        async def execute(state: RuntimeState) -> RuntimeState:
            if on_route is not None:
                on_route(route)
            agent = self._agents[route.value]
            request = self._request_message(task.task_id, route, agent.name, context)
            context.messages.append(request)
            self._emit(EventType.AGENT_STARTED, task.task_id, agent.name, {"route": route.value})
            if route is AgentRoute.VERIFICATION:
                self._emit(EventType.VERIFICATION_STARTED, task.task_id, agent.name)
            try:
                result = await self.pipeline.execute_stage(PipelineStage(self._task_status(route), agent), context)
                if not result.success:
                    raise ModuleExecutionError(result.error or f"Agent failed: {result.agent_name}")
                for message in result.messages:
                    ensure_public_trace_payload(message.payload)
                self._validate_finding_authority(route, result, context)
            except Exception as exc:
                error_message = AgentMessage(
                    message_id=new_message_id(),
                    task_id=task.task_id,
                    sender=agent.name,
                    receiver="orchestrator",
                    message_type=AgentMessageType.ERROR,
                    payload={
                        "route": route.value,
                        "error": "agent execution failed",
                        "error_type": type(exc).__name__,
                    },
                )

                context.messages.append(
                    error_message
                )

                self._emit(
                    EventType.AGENT_FINISHED,
                    task.task_id,
                    agent.name,
                    {
                        "route": route.value,
                        "success": False,
                        "error": "agent execution failed",
                        "error_type": type(exc).__name__,
                    },
                )

                history = [
                    *state["route_history"],
                    route.value,
                ]

                messages = [
                    *state["messages"],
                    request,
                    error_message,
                ]

                metadata = dict(
                    state["runtime_metadata"]
                )

                metadata["force_fallback_reason"] = (
                    "agent execution failed: "
                    f"{route.value}"
                )

                metadata["last_agent_error"] = {
                    "route": route.value,
                    "agent": agent.name,
                    "error": "agent execution failed",
                    "error_type": type(exc).__name__,
                }

                return {
                    **state,
                    "current_agent": route.value,
                    "next_agent": None,
                    "step_count": state["step_count"] + 1,
                    "route_history": history,
                    "messages": messages,
                    "runtime_metadata": metadata,
                }
            self.pipeline.merge(context, result, replace_findings=route is AgentRoute.VERIFICATION)
            self._emit_result_events(task.task_id, route, result)
            self._emit(EventType.AGENT_FINISHED, task.task_id, agent.name, {"route": route.value, "success": True})
            history = [*state["route_history"], route.value]
            completed = [*state["completed_agents"], agent.name]
            messages = [*state["messages"], request, *result.messages]
            return {
                **state,
                "current_agent": route.value,
                "next_agent": None,
                "step_count": state["step_count"] + 1,
                "route_history": history,
                "messages": messages,
                "completed_agents": completed,
            }

        return execute

    @staticmethod
    def _validate_finding_authority(route: AgentRoute, result, context: AnalysisContext) -> None:
        discovery = {AgentRoute.SOURCE_ANALYSIS, AgentRoute.BINARY_ANALYSIS, AgentRoute.FUZZ}
        if route in discovery:
            available_evidence = {item.evidence_id for item in [*context.evidence, *result.evidence]}
            for finding in result.findings:
                if finding.status.value != "candidate":
                    raise ModuleExecutionError(f"Discovery agent cannot emit final status: {finding.status.value}")
                if not finding.evidence_ids or not set(finding.evidence_ids).issubset(available_evidence):
                    raise ModuleExecutionError(f"Discovery candidate lacks stored evidence: {finding.vulnerability_id}")
            return
        if route is AgentRoute.VERIFICATION:
            allowed = {"confirmed", "rejected", "uncertain"}
            invalid = [item.status.value for item in result.findings if item.status.value not in allowed]
            if invalid:
                raise ModuleExecutionError(f"Verification returned non-final status: {invalid[0]}")
            return
        if result.findings:
            raise ModuleExecutionError(f"Agent is not authorized to write findings: {route.value}")

    @staticmethod
    def _request_message(task_id: str, route: AgentRoute, receiver: str, context: AnalysisContext) -> AgentMessage:
        message_type = {
            AgentRoute.PLANNER: AgentMessageType.TASK,
            AgentRoute.SOURCE_ANALYSIS: AgentMessageType.REQUEST_ANALYSIS,
            AgentRoute.BINARY_ANALYSIS: AgentMessageType.REQUEST_ANALYSIS,
            AgentRoute.FUZZ: AgentMessageType.FUZZ_REQUEST,
            AgentRoute.VERIFICATION: AgentMessageType.REQUEST_VERIFICATION,
            AgentRoute.REVIEWER: AgentMessageType.REVIEW_REQUEST,
            AgentRoute.REPORT: AgentMessageType.REPORT_REQUEST,
        }[route]
        evidence_ids = sorted({evidence_id for finding in context.findings for evidence_id in finding.evidence_ids})
        return AgentMessage(
            message_id=new_message_id(),
            task_id=task_id,
            sender="supervisor",
            receiver=receiver,
            message_type=message_type,
            payload={"route": route.value, "finding_count": len(context.findings)},
            evidence_ids=evidence_ids,
        )

    def _emit_result_events(self, task_id: str, route: AgentRoute, result) -> None:
        for finding in result.findings:
            if route in {AgentRoute.SOURCE_ANALYSIS, AgentRoute.BINARY_ANALYSIS, AgentRoute.FUZZ}:
                self._emit(EventType.CANDIDATE_CREATED, task_id, result.agent_name, {"vulnerability_id": finding.vulnerability_id})
            if route is AgentRoute.VERIFICATION and finding.status.value == "confirmed":
                self._emit(EventType.VULNERABILITY_CONFIRMED, task_id, result.agent_name, {"vulnerability_id": finding.vulnerability_id})
            if route is AgentRoute.VERIFICATION and finding.status.value == "rejected":
                self._emit(EventType.VULNERABILITY_REJECTED, task_id, result.agent_name, {"vulnerability_id": finding.vulnerability_id})
        if route is AgentRoute.REVIEWER:
            self._emit(EventType.REVIEW_COMPLETED, task_id, result.agent_name)
        if route is AgentRoute.REPORT and result.reports:
            self._emit(EventType.REPORT_GENERATED, task_id, result.agent_name)

    def _emit(self, event_type: EventType, task_id: str, producer: str, payload: dict[str, object] | None = None) -> None:
        if self.publish_event is not None:
            self.publish_event(DomainEvent(event_type=event_type, task_id=task_id, producer=producer, payload=payload or {}))

    @staticmethod
    def _public_route_decision(
        decision: RouteDecision,
    ) -> RouteDecision:
        """Keep route reasons concise and metadata structurally public."""

        ensure_public_trace_payload(decision.metadata)

        reason = decision.reason
        if (
            not isinstance(reason, str)
            or len(reason) > 256
            or "\n" in reason
            or "\r" in reason
        ):
            reason = "supervisor supplied a non-public route reason"

        return RouteDecision(
            route=decision.route,
            reason=reason,
            fallback_used=decision.fallback_used,
            metadata=dict(decision.metadata),
        )

    @staticmethod
    def _task_status(route: AgentRoute) -> TaskStatus:
        return {
            AgentRoute.PLANNER: TaskStatus.PLANNING,
            AgentRoute.SOURCE_ANALYSIS: TaskStatus.ANALYZING,
            AgentRoute.BINARY_ANALYSIS: TaskStatus.ANALYZING,
            AgentRoute.FUZZ: TaskStatus.DYNAMIC_TESTING,
            AgentRoute.VERIFICATION: TaskStatus.VERIFYING,
            AgentRoute.REVIEWER: TaskStatus.VERIFYING,
            AgentRoute.REPORT: TaskStatus.REPORTING,
        }[route]
