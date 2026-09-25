"""WP5: benchmark adaptation package (blind evaluation protocol)."""

from vulnagent.benchmark.adapters import (
    ExploitGymDiscoveryAdapter,
    ScreeningRecord,
    VulnGymCatalogBuilder,
)
from vulnagent.benchmark.evaluator import BlindEvaluator
from vulnagent.benchmark.leakage import LabelLeakageGuard
from vulnagent.benchmark.schema import (
    AuthorizationFlags,
    BlindCaseManifest,
    BlindEligibility,
    CaseOutcome,
    CaseRunStatus,
    DatasetName,
    EvaluationResult,
    GroundTruth,
    LabelLeakReport,
    Role,
    TargetKind,
)

__all__ = [
    "AuthorizationFlags",
    "BlindCaseManifest",
    "BlindEligibility",
    "BlindEvaluator",
    "CaseOutcome",
    "CaseRunStatus",
    "DatasetName",
    "EvaluationResult",
    "ExploitGymDiscoveryAdapter",
    "GroundTruth",
    "LabelLeakReport",
    "LabelLeakageGuard",
    "Role",
    "ScreeningRecord",
    "TargetKind",
    "VulnGymCatalogBuilder",
]
