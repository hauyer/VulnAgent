"""Persistence port for completed or failed analysis contexts."""

from __future__ import annotations

from typing import Protocol

from vulnagent.contracts import AnalysisContext


class ContextRepository(Protocol):
    """Store the aggregate needed by findings, verification and report APIs."""

    def save_context(self, context: AnalysisContext) -> AnalysisContext: ...

    def get_context(self, task_id: str) -> AnalysisContext | None: ...


class InMemoryContextStore:
    """Process-local context adapter used by tests and the default profile."""

    def __init__(self) -> None:
        self._contexts: dict[str, AnalysisContext] = {}

    def save_context(self, context: AnalysisContext) -> AnalysisContext:
        snapshot = context.model_copy(deep=True)
        self._contexts[context.task.task_id] = snapshot
        return snapshot.model_copy(deep=True)

    def get_context(self, task_id: str) -> AnalysisContext | None:
        context = self._contexts.get(task_id)
        return None if context is None else context.model_copy(deep=True)


__all__ = ["ContextRepository", "InMemoryContextStore"]
