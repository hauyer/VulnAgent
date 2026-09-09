import pytest

from vulnagent.agents.planner_agent import (
    PlannerAgent,
)
from vulnagent.agents.registry import (
    AgentRegistry,
)
from vulnagent.agents.reviewer_agent import (
    ReviewerAgent,
)


def test_register_get_and_list() -> None:
    registry = AgentRegistry()

    agent = PlannerAgent()

    registry.register(agent)

    assert registry.get("planner") is agent

    assert registry.list_agents() == [
        "planner"
    ]

    assert "planner" in registry
    assert len(registry) == 1

    with pytest.raises(
        ValueError,
        match="Agent already registered",
    ):
        registry.register(
            PlannerAgent()
        )


def test_register_with_logical_key() -> None:
    registry = AgentRegistry()

    agent = ReviewerAgent()

    registry.register(
        agent,
        key="custom_reviewer_route",
    )

    assert (
        registry.get(
            "custom_reviewer_route"
        )
        is agent
    )

    assert registry.list_agents() == [
        "custom_reviewer_route"
    ]


def test_register_many_with_route_mapping() -> None:
    registry = AgentRegistry()

    planner = PlannerAgent()
    reviewer = ReviewerAgent()

    registry.register_many(
        {
            "planner": planner,
            "reviewer": reviewer,
        }
    )

    assert registry.as_mapping() == {
        "planner": planner,
        "reviewer": reviewer,
    }


def test_register_many_is_atomic() -> None:
    registry = AgentRegistry()

    registry.register(
        PlannerAgent()
    )

    with pytest.raises(
        ValueError,
        match="Agent already registered",
    ):
        registry.register_many(
            {
                "planner":
                    ReviewerAgent(),

                "reviewer":
                    ReviewerAgent(),
            }
        )

    assert registry.list_agents() == [
        "planner"
    ]


def test_unknown_agent_raises_key_error() -> None:
    registry = AgentRegistry()

    with pytest.raises(
        KeyError,
        match="Unknown agent",
    ):
        registry.get(
            "missing"
        )


def test_invalid_agent_key_rejected() -> None:
    registry = AgentRegistry()

    with pytest.raises(
        ValueError,
        match="cannot be empty",
    ):
        registry.register(
            PlannerAgent(),
            key="",
        )

    with pytest.raises(
        ValueError,
        match="leading or trailing whitespace",
    ):
        registry.register(
            PlannerAgent(),
            key=" planner ",
        )