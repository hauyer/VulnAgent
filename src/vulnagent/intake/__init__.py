"""Target admission framework for the vulnerability-discovery practice.

A read-only gate that registers, authorizes, version-pins and hashes targets
before analysis.  It never executes a target.  Hidden ground-truth labels are
kept out of agent-facing payloads.
"""

from .hashing import fingerprint_target, sha256_file, target_size
from .loader import load_manifest, load_manifest_dir, load_suite, normalize_manifest_dict
from .models import (
    Authorization,
    DatasetRole,
    IntakeDecision,
    IntakeReason,
    TargetKind,
    TargetManifest,
)
from .validator import (
    DefaultTargetIntake,
    LabelLeakError,
    TargetIntake,
    assert_ground_truth_isolated,
    find_label_leaks,
)

__all__ = [
    "Authorization",
    "DatasetRole",
    "DefaultTargetIntake",
    "IntakeDecision",
    "IntakeReason",
    "LabelLeakError",
    "TargetIntake",
    "TargetKind",
    "TargetManifest",
    "assert_ground_truth_isolated",
    "find_label_leaks",
    "fingerprint_target",
    "load_manifest",
    "load_manifest_dir",
    "load_suite",
    "normalize_manifest_dict",
    "sha256_file",
    "target_size",
]
