"""PUBLIC CONTRACT: normalized cross-module exceptions."""
class VulnAgentError(Exception):
    """Base expected failure."""
class ModuleExecutionError(VulnAgentError):
    """Capability execution failed."""
class ToolUnavailableError(VulnAgentError):
    """Optional tool is unavailable."""
class ModuleTimeoutError(VulnAgentError):
    """Bounded operation timed out."""
class ContractValidationError(VulnAgentError):
    """Data violated a public contract."""
