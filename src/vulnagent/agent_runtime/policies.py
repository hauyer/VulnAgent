"""Safety and routing limits for agent workflows."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuntimePolicy:
    """Bound every workflow and every repeated route."""

    max_agent_steps: int = 15
    max_route_repeats: int = 2
    max_analysis_retries: int = 1

    def __post_init__(self) -> None:
        if self.max_agent_steps < 1:
            raise ValueError("max_agent_steps must be positive")
        if self.max_route_repeats < 1:
            raise ValueError("max_route_repeats must be positive")
        if self.max_analysis_retries < 0:
            raise ValueError("max_analysis_retries cannot be negative")
