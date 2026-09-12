"""Local-only course test laboratory.

The package adds orchestration ViewModels around the existing VulnAgent
pipeline.  It deliberately does not redefine the frozen public contracts.
"""

from .models import (
    BinaryLabTarget,
    LabArchiveResult,
    LabCapability,
    LabCategory,
    LabLogEntry,
    LabRun,
    LabRunRequest,
    LabRunState,
    LabTargetResult,
    LocalModelTarget,
)
from .service import TestLabService
from .llm_vuln_scanner import (
    LLMArchiveResult,
    LLMProbeResult,
    LLMScanProgress,
    LLMScanRequest,
    LLMScanResult,
    LLMVulnerabilityScanner,
    LLMVulnerabilityType,
    OllamaModelOption,
)

__all__ = [
    "BinaryLabTarget",
    "LabArchiveResult",
    "LabCapability",
    "LabCategory",
    "LabLogEntry",
    "LabRun",
    "LabRunRequest",
    "LabRunState",
    "LabTargetResult",
    "LocalModelTarget",
    "TestLabService",
    "LLMArchiveResult",
    "LLMProbeResult",
    "LLMScanProgress",
    "LLMScanRequest",
    "LLMScanResult",
    "LLMVulnerabilityScanner",
    "LLMVulnerabilityType",
    "OllamaModelOption",
]
