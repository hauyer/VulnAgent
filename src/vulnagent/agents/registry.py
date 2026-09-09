"""In-process registry for injected VulnAgent agents.

The registry intentionally separates the stable runtime route key from
``BaseAgent.name``.

Example:

    runtime key:
        source_analysis

    agent identity:
        source_audit

AgentRuntime routes by the stable workflow key while Agent.name remains
the identity used in AgentMessage, DomainEvent and trace output.
"""

from collections.abc import Iterable, Mapping

from vulnagent.agents.base import BaseAgent


class AgentRegistry:
    """Register and resolve agents using stable logical runtime keys."""

    def __init__(self) -> None:
        self._agents: dict[str, BaseAgent] = {}

    def register(
        self,
        agent: BaseAgent,
        *,
        key: str | None = None,
    ) -> None:
        """Register one agent.

        Args:
            agent:
                Concrete BaseAgent implementation.

            key:
                Optional logical runtime key.  If omitted, ``agent.name``
                is used for backward compatibility.
        """

        resolved_key = self._resolve_key(
            agent,
            key,
        )

        if resolved_key in self._agents:
            raise ValueError(
                f"Agent already registered: {resolved_key}"
            )

        self._agents[resolved_key] = agent

    def register_many(
        self,
        agents: Mapping[str, BaseAgent] | Iterable[BaseAgent],
    ) -> None:
        """Atomically register several agents.

        Mapping form:

            {
                "source_analysis": source_agent,
                "verification": verification_agent,
            }

        Iterable form preserves the previous behaviour and uses each
        ``agent.name`` as the key.
        """

        if isinstance(agents, Mapping):
            pending = [
                (
                    self._validate_key(key),
                    agent,
                )
                for key, agent in agents.items()
            ]

        else:
            pending = [
                (
                    self._resolve_key(
                        agent,
                        None,
                    ),
                    agent,
                )
                for agent in agents
            ]

        existing_keys = set(self._agents)
        batch_keys: set[str] = set()

        for key, _agent in pending:
            self._validate_agent(_agent)

            if key in existing_keys:
                raise ValueError(
                    f"Agent already registered: {key}"
                )

            if key in batch_keys:
                raise ValueError(
                    "Duplicate agent key in registration batch: "
                    f"{key}"
                )

            batch_keys.add(key)

        for key, agent in pending:
            self._agents[key] = agent

    def get(
        self,
        name: str,
    ) -> BaseAgent:
        """Resolve one agent by logical registry key."""

        try:
            return self._agents[name]

        except KeyError as exc:
            raise KeyError(
                f"Unknown agent: {name}"
            ) from exc

    def contains(
        self,
        name: str,
    ) -> bool:
        """Return whether an agent key is registered."""

        return name in self._agents

    def list_agents(
        self,
    ) -> list[str]:
        """Return logical agent keys in registration order."""

        return list(self._agents)

    def as_mapping(
        self,
    ) -> dict[str, BaseAgent]:
        """Return a defensive mapping suitable for AgentRuntime."""

        return dict(self._agents)

    def __contains__(
        self,
        name: object,
    ) -> bool:
        """Support ``name in registry``."""

        return (
            isinstance(name, str)
            and name in self._agents
        )

    def __len__(
        self,
    ) -> int:
        """Return the number of registered agents."""

        return len(self._agents)

    @classmethod
    def _resolve_key(
        cls,
        agent: BaseAgent,
        key: str | None,
    ) -> str:
        """Resolve explicit logical key or fall back to agent.name."""

        cls._validate_agent(agent)

        resolved_key = (
            key
            if key is not None
            else agent.name
        )

        return cls._validate_key(
            resolved_key
        )

    @staticmethod
    def _validate_agent(agent: BaseAgent) -> None:
        """Reject registry entries outside the canonical BaseAgent boundary."""

        if not isinstance(agent, BaseAgent):
            raise TypeError(
                "Agent registry entries must inherit BaseAgent"
            )

    @staticmethod
    def _validate_key(
        key: str,
    ) -> str:
        """Validate a logical agent registry key."""

        if not isinstance(key, str):
            raise ValueError(
                "Agent registry key must be a string"
            )

        if not key:
            raise ValueError(
                "Agent registry key cannot be empty"
            )

        if key.strip() != key:
            raise ValueError(
                "Agent registry key cannot contain "
                "leading or trailing whitespace"
            )

        return key
