import pytest

from vulnagent.agents.planner_agent import PlannerAgent
from vulnagent.agents.registry import AgentRegistry


def test_register_get_and_list() -> None:
    registry = AgentRegistry()
    agent = PlannerAgent()
    registry.register(agent)
    assert registry.get("planner") is agent
    assert registry.list_agents() == ["planner"]
    with pytest.raises(ValueError):
        registry.register(PlannerAgent())

