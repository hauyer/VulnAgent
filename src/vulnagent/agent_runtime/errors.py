"""Expected agent runtime failures."""


class AgentRuntimeError(RuntimeError):
    """Base error raised by the bounded agent runtime."""


class AgentStepLimitReached(AgentRuntimeError):
    """Raised only when callers explicitly request hard step-limit failure."""


class ToolRegistrationError(AgentRuntimeError):
    """A logical capability tool could not be registered or resolved."""
