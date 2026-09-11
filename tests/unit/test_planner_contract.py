import pytest

from vulnagent.agents.planner_agent import PlannerAgent
from vulnagent.contracts import (
    AnalysisContext,
    Target,
    TargetType,
    Task,
)


def make_task(
    target_type: TargetType,
    metadata: dict[str, object] | None = None,
) -> Task:
    return Task(
        task_id="task",
        target=Target(
            target_id="target",
            path="fixture",
            target_type=target_type,
            metadata=metadata or {},
        ),
    )


@pytest.mark.parametrize(
    ("target_type", "analysis_agent", "capabilities"),
    [
        (
            TargetType.SOURCE,
            "source_audit",
            {"source.parse", "source.audit"},
        ),
        (
            TargetType.BINARY,
            "binary_analysis",
            {"binary.inspect", "binary.logic", "binary.obfuscation"},
        ),
    ],
)
async def test_planner_emits_structured_plan_contract(
    target_type: TargetType,
    analysis_agent: str,
    capabilities: set[str],
) -> None:
    task = make_task(target_type)

    result = await PlannerAgent().run(task, AnalysisContext(task=task))

    assert result.findings == []
    assert result.evidence == []
    assert len(result.messages) == 1
    payload = result.messages[0].payload
    assert set(payload) == {
        "selected_agents",
        "requested_capabilities",
        "priorities",
        "stop_conditions",
        "rationale_summary",
        "metadata",
    }
    assert payload["selected_agents"][0] == analysis_agent
    assert set(payload["requested_capabilities"]) == capabilities


async def test_planner_requests_fuzz_only_with_both_safety_flags() -> None:
    planner = PlannerAgent()

    for metadata, expected in [
        ({}, False),
        ({"fuzz_authorized": True}, False),
        ({"dynamic_validation": True}, False),
        (
            {"fuzz_authorized": True, "dynamic_validation": True},
            True,
        ),
    ]:
        task = make_task(TargetType.SOURCE, metadata)
        result = await planner.run(task, AnalysisContext(task=task))
        selected = result.messages[0].payload["selected_agents"]
        requested = result.messages[0].payload["requested_capabilities"]
        assert ("fuzz" in selected) is expected
        assert ("fuzz.execute" in requested) is expected
