"""Structured planning agent with a bounded LLM advisory path."""

import json
from typing import Any

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, TargetType, Task
from vulnagent.llm.base import BaseLLM
from vulnagent.utils.ids import new_message_id


class PlannerAgent(BaseAgent):
    """Describe intended agents and capabilities without executing them."""

    name = "planner"

    def __init__(self, llm: BaseLLM | None = None) -> None:
        self.llm = llm

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        analyzer = "binary_analysis" if task.target.target_type is TargetType.BINARY else "source_audit"
        selected_agents = [analyzer, "verification", "reviewer", "report"]
        requested_capabilities = (
            ["binary.inspect", "binary.logic", "binary.obfuscation"]
            if analyzer == "binary_analysis"
            else ["source.parse", "source.audit"]
        )
        if task.target.metadata.get("fuzz_authorized") and task.target.metadata.get("dynamic_validation"):
            selected_agents.insert(1, "fuzz")
            requested_capabilities.append("fuzz.execute")
        advisory = await self._advisory(
            task,
            selected_agents,
            requested_capabilities,
        )
        rationale = str(
            advisory.get("rationale_summary")
            or f"Use {analyzer} for target type {task.target.target_type.value}."
        )[:500]
        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="supervisor",
            message_type=AgentMessageType.PLAN,
            payload={
                "selected_agents": selected_agents,
                "rationale_summary": rationale,
                "priorities": {name: index + 1 for index, name in enumerate(selected_agents)},
                "requested_capabilities": requested_capabilities,
                "stop_conditions": ["report_generated", "max_agent_steps_reached"],
                "metadata": {
                    "dynamic": True,
                    "llm_advisory": advisory,
                    "routing_authority": "deterministic_supervisor",
                },
            },
        )
        return AgentResult(agent_name=self.name, messages=[message])

    async def _advisory(
        self,
        task: Task,
        selected_agents: list[str],
        requested_capabilities: list[str],
    ) -> dict[str, Any]:
        """Ask an injected model for non-authoritative structured advice."""
        if self.llm is None:
            return {"used": False, "status": "not_configured", "risk_focus": []}
        prompt = json.dumps(
            {
                "task": "prioritize a bounded vulnerability analysis plan",
                "target": {
                    "target_type": task.target.target_type.value,
                    "language": task.target.language,
                    "file_format": task.target.file_format,
                },
                "allowed_agents": selected_agents,
                "mandatory_capabilities": requested_capabilities,
                "output_schema": {
                    "rationale_summary": "single-line string",
                    "risk_focus": ["short structured labels"],
                },
                "constraints": [
                    "return JSON only",
                    "do not propose exploitation",
                    "do not reveal chain-of-thought",
                    "the deterministic supervisor remains route authority",
                ],
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        try:
            response = await self.llm.generate(
                prompt,
                system_prompt=(
                    "You are a vulnerability-analysis planning advisor. Return "
                    "only compact JSON matching the requested public schema."
                ),
                max_tokens=256,
                temperature=0.0,
                response_format={"type": "json_object"},
                thinking={"type": "disabled"},
            )
            parsed = json.loads(response)
            if not isinstance(parsed, dict):
                raise ValueError("advisory response is not an object")
            raw_focus = parsed.get("risk_focus", [])
            risk_focus = (
                [str(item)[:80] for item in raw_focus[:8]]
                if isinstance(raw_focus, list)
                else []
            )
            raw_rationale = parsed.get("rationale_summary")
            rationale = (
                str(raw_rationale).replace("\r", " ").replace("\n", " ")[:500]
                if raw_rationale
                else None
            )
            return {
                "used": True,
                "status": "accepted",
                "provider": type(self.llm).__name__,
                "rationale_summary": rationale,
                "risk_focus": risk_focus,
            }
        except Exception as exc:
            return {
                "used": True,
                "status": "fallback",
                "provider": type(self.llm).__name__,
                "error_type": type(exc).__name__,
                "risk_focus": [],
            }
