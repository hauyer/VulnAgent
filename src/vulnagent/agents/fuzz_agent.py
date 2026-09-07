"""Mock fuzz agent; it records evidence without executing a target."""

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Evidence, EvidenceType, FuzzEngine, FuzzRequest, Task
from vulnagent.utils.ids import new_evidence_id, new_message_id


class FuzzAgent(BaseAgent):
    """Invoke an injected fuzz protocol while preserving authorization metadata."""

    name = "fuzz"

    def __init__(self, engine: FuzzEngine) -> None:
        self.engine = engine

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        authorized = bool(task.target.metadata.get("fuzz_authorized", False))
        fuzz_result = await self.engine.run(FuzzRequest(task_id=task.task_id, target_id=task.target.target_id, target_path=task.target.path, authorized=authorized))
        evidence = Evidence(evidence_id=new_evidence_id(), task_id=task.task_id, evidence_type=EvidenceType.TOOL_RESULT, source="mock_fuzzer", description="Mock fuzz stage completed without executing the target.", data={"mock": True, "authorized": authorized, "executed": fuzz_result.executed, "crashes": fuzz_result.crashes}, reliability=0.3, created_by=self.name)
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, receiver="verification", message_type=AgentMessageType.FUZZ_RESULT, payload=fuzz_result.model_dump(mode="json", exclude={"evidence"}), evidence_ids=[evidence.evidence_id])
        return AgentResult(agent_name=self.name, messages=[message], evidence=[evidence])
