"""Mock fuzz agent; it records evidence without executing a target."""

from vulnagent.agents.base import BaseAgent
from vulnagent.core.models import AgentMessage, AgentMessageType, AgentResult, AnalysisContext, Evidence, EvidenceType, Task
from vulnagent.utils.ids import new_evidence_id, new_message_id


class FuzzAgent(BaseAgent):
    name = "fuzz"

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        evidence = Evidence(evidence_id=new_evidence_id(), task_id=task.task_id, evidence_type=EvidenceType.TOOL_RESULT, source="mock_fuzzer", description="Mock fuzz stage completed without executing the target.", data={"mock": True, "executed": False, "crashes": 0}, reliability=0.3, created_by=self.name)
        message = AgentMessage(message_id=new_message_id(), task_id=task.task_id, sender=self.name, receiver="verification", message_type=AgentMessageType.FUZZ_RESULT, payload={"mock": True, "executed": False}, evidence_ids=[evidence.evidence_id])
        return AgentResult(agent_name=self.name, messages=[message], evidence=[evidence])

