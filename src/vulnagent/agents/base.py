"""Common agent contract."""

from abc import ABC, abstractmethod

from vulnagent.core.models import AgentResult, AnalysisContext, Task


class BaseAgent(ABC):
    """Base interface implemented by every agent."""

    name: str

    @abstractmethod
    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        """Run the agent without mutating global state."""

