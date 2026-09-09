from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import (
    AgentResult,
    AnalysisContext,
    Evidence,
    EvidenceType,
    Target,
    TargetType,
    Task,
    TaskStatus,
    VulnerabilityCandidate,
)
from vulnagent.core.pipeline import Pipeline, PipelineStage


def make_context() -> AnalysisContext:
    task = Task(
        task_id="task",
        target=Target(
            target_id="target",
            path="fixture",
            target_type=TargetType.SOURCE,
        ),
    )
    return AnalysisContext(task=task)


def make_finding(identifier: str) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id=identifier,
        task_id="task",
        title=identifier,
        vulnerability_type="test",
        description="test finding",
        target_id="target",
        source_agent="test",
        confidence=0.5,
    )


class RecordingAgent(BaseAgent):
    name = "recording"

    def __init__(self, result: AgentResult) -> None:
        self.result = result
        self.calls = 0

    async def run(
        self,
        task: Task,
        context: AnalysisContext,
    ) -> AgentResult:
        self.calls += 1
        assert task is context.task
        return self.result


async def test_execute_stage_runs_only_the_supplied_agent() -> None:
    result = AgentResult(agent_name="recording")
    agent = RecordingAgent(result)
    context = make_context()

    returned = await Pipeline().execute_stage(
        PipelineStage(TaskStatus.ANALYZING, agent),
        context,
    )

    assert returned is result
    assert agent.calls == 1


def test_merge_aggregates_one_stage_result() -> None:
    context = make_context()
    finding = make_finding("finding-1")
    evidence = Evidence(
        evidence_id="evidence-1",
        task_id="task",
        evidence_type=EvidenceType.TOOL_RESULT,
        source="test",
        description="test evidence",
        reliability=0.5,
        created_by="test",
    )
    result = AgentResult(
        agent_name="test",
        findings=[finding],
        evidence=[evidence],
        artifacts=["artifact"],
    )

    Pipeline.merge(context, result)

    assert context.findings == [finding]
    assert context.evidence == [evidence]
    assert context.artifacts == ["artifact"]


def test_verification_merge_replaces_discovery_findings() -> None:
    context = make_context()
    original = make_finding("original")
    verified = make_finding("verified")
    context.findings = [original]

    Pipeline.merge(
        context,
        AgentResult(agent_name="verification", findings=[verified]),
        replace_findings=True,
    )

    assert context.findings == [verified]
