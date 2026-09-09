"""Structured planning agent for the V0.2 runtime."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, TargetType, Task
from vulnagent.utils.ids import new_message_id


class PlannerAgent(BaseAgent):
    """Describe intended agents and capabilities without executing them."""

    name = "planner"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        analyzer = "binary_analysis" if task.target.target_type is TargetType.BINARY else "source_audit"
        selected_agents = [analyzer, "verification", "reviewer", "report"]
        requested_capabilities = ["binary.inspect"] if analyzer == "binary_analysis" else ["source.parse", "source.audit"]
        if task.target.metadata.get("fuzz_authorized") and task.target.metadata.get("dynamic_validation"):
            selected_agents.insert(1, "fuzz")
            requested_capabilities.append("fuzz.execute")
        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="supervisor",
            message_type=AgentMessageType.PLAN,
            payload={
                "selected_agents": selected_agents,
                "rationale_summary": f"Use {analyzer} for target type {task.target.target_type.value}.",
                "priorities": {name: index + 1 for index, name in enumerate(selected_agents)},
                "requested_capabilities": requested_capabilities,
                "stop_conditions": ["report_generated", "max_agent_steps_reached"],
                "metadata": {"mock_llm": True, "dynamic": True},
            },
        )
        return AgentResult(agent_name=self.name, messages=[message])
