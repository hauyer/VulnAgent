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

        async def supervise(state: RuntimeState) -> RuntimeState:
            proposed = self.supervisor.decide(task, context, state)
            decision = self.router.resolve(proposed.route, state["route_history"])
            metadata = dict(state["runtime_metadata"])
            if decision.fallback_used:
                metadata["fallback_used"] = True
                metadata["termination_reason"] = decision.reason
                if "step limit" in decision.reason:
                    metadata["step_limit_reached"] = True
            self._emit(
                EventType.AGENT_ROUTED,
                task.task_id,
                "supervisor",
                {"route": decision.route.value, "reason": decision.reason, "fallback_used": decision.fallback_used},
            )
            if proposed.metadata.get("retry"):
                self._emit(EventType.AGENT_RETRY, task.task_id, "supervisor", {"route": decision.route.value})
            return {**state, "next_agent": decision.route.value, "runtime_metadata": metadata}

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
                self._validate_finding_authority(route, result, context)
            except Exception as exc:
                context.messages.append(
                    AgentMessage(
                        message_id=new_message_id(),
                        task_id=task.task_id,
                        sender=agent.name,
                        receiver="orchestrator",
                        message_type=AgentMessageType.ERROR,
                        payload={"route": route.value, "error": str(exc)},
                    )
                )
                self._emit(EventType.AGENT_FINISHED, task.task_id, agent.name, {"route": route.value, "success": False, "error": str(exc)})
                raise
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
        if route is AgentRoute.REPORT:
            self._emit(EventType.REPORT_GENERATED, task_id, result.agent_name)

    def _emit(self, event_type: EventType, task_id: str, producer: str, payload: dict[str, object] | None = None) -> None:
        if self.publish_event is not None:
            self.publish_event(DomainEvent(event_type=event_type, task_id=task_id, producer=producer, payload=payload or {}))

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
