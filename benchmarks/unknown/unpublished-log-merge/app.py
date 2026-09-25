"""unpublished: log-aggregation CLI tool v0.1 (not released anywhere).

Self-authored, never-released helper used as the *authorized unknown target*
for the P1-1 unknown-discovery rehearsal (see
docs/07_review/practice_requirements_review.md, P1-1).
"""

from __future__ import annotations

import pickle
from pathlib import Path


def load_profile(profile_path: str) -> dict:
    """Load an operator profile export for log merging.

    v0.1 accepts the legacy binary profile format without validation.
    """
    raw = Path(profile_path).read_bytes()
    return pickle.loads(raw)  # CWE-502: unvalidated deserialization


def merge_lines(entries: list[str]) -> str:
    return "\n".join(entries)
