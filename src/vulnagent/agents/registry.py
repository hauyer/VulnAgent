"""Simple in-process agent registry."""

from vulnagent.agents.base import BaseAgent


class AgentRegistry:
    """Register and retrieve agents by unique name."""

    def __init__(self) -> None:
        self._agents: dict[str, BaseAgent] = {}

    def register(self, agent: BaseAgent) -> None:
        if agent.name in self._agents:
            raise ValueError(f"Agent already registered: {agent.name}")
        self._agents[agent.name] = agent

    def get(self, name: str) -> BaseAgent:
        try:
            return self._agents[name]
        except KeyError as exc:
            raise KeyError(f"Unknown agent: {name}") from exc

    def list_agents(self) -> list[str]:
        return list(self._agents)

