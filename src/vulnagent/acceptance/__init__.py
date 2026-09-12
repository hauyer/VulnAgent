"""Course-test acceptance matrix: read-only aggregation and honest status.

This package exposes ``NOT_RUN/RUNNING/PASS/PARTIAL/FAIL/BLOCKED`` status for
the three course test groups (LLM, packed closed-source, obfuscated
closed-source). Status is computed from manifests, experiment artifacts and
provider configuration only -- never hardcoded and never derived from model
natural language. It does not modify any frozen public Schema.
"""

from vulnagent.acceptance.models import (
    AcceptanceCondition,
    AcceptanceGroup,
    AcceptanceOverview,
    AcceptanceStatus,
    AcceptanceTarget,
    BenchmarkCounts,
    BenchmarkSummary,
    BinaryBenchmarkMetric,
    ElfBenchmarkSummary,
    LLMComparisonSummary,
    ProviderComparison,
    ProviderStatus,
)
from vulnagent.acceptance.calculator import AcceptanceCalculator
from vulnagent.acceptance.batches import (
    AcceptanceBatchStore,
    CustomAcceptanceBatch,
    CustomAcceptanceBatchCreate,
)

__all__ = [
    "AcceptanceCalculator",
    "AcceptanceCondition",
    "AcceptanceGroup",
    "AcceptanceOverview",
    "AcceptanceStatus",
    "AcceptanceBatchStore",
    "AcceptanceTarget",
    "BenchmarkCounts",
    "BenchmarkSummary",
    "BinaryBenchmarkMetric",
    "ElfBenchmarkSummary",
    "LLMComparisonSummary",
    "ProviderComparison",
    "ProviderStatus",
    "CustomAcceptanceBatch",
    "CustomAcceptanceBatchCreate",
]
