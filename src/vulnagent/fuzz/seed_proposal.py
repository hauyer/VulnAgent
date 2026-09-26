"""Fuzz plateau detection and seed proposal (L8, roadmap §2.1).

Documents a plateau event (e.g. 60/120 seconds without new coverage) and lets
an optional ``SeedProposalProvider`` *suggest* new inputs from the existing
corpus without executing the target.  The provider is deterministic, bounded
and purely advisory — the FuzzAgent decides whether to adopt any suggestion.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True, slots=True)
class PlateauSignal:
    plateau: bool
    stalled_seconds: float
    executions_without_new_coverage: int
    threshold_seconds: float
    note: str = ""


class PlateauDetector:
    """Track wall-clock stalls in new coverage."""

    def __init__(self, threshold_seconds: float = 60.0) -> None:
        if threshold_seconds <= 0:
            raise ValueError("threshold_seconds must be positive")
        self.threshold_seconds = threshold_seconds
        self.last_new_coverage_at: float | None = None
        self.executions_without_new_coverage = 0

    def update(self, now: float, new_coverage: bool) -> PlateauSignal:
        """Feed one observation; returns the current plateau signal."""
        if new_coverage:
            self.last_new_coverage_at = now
            self.executions_without_new_coverage = 0
        else:
            self.executions_without_new_coverage += 1
        stalled = 0.0
        if self.last_new_coverage_at is not None:
            stalled = now - self.last_new_coverage_at
        plateau = self.last_new_coverage_at is not None and stalled >= self.threshold_seconds
        return PlateauSignal(
            plateau=plateau,
            stalled_seconds=stalled,
            executions_without_new_coverage=self.executions_without_new_coverage,
            threshold_seconds=self.threshold_seconds,
            note=(
                f"{stalled:.0f}s without new coverage "
                f"(threshold {self.threshold_seconds:.0f}s)"
                if plateau
                else "coverage still advancing"
            ),
        )


class SeedProposalProvider(Protocol):
    def propose(
        self,
        corpus: list[bytes],
        plateau: PlateauSignal,
        *,
        seed: int,
        max_proposals: int = 8,
    ) -> list[bytes]:
        """Suggest candidate inputs (never executed here)."""


class DeterministicSeedProposalProvider:
    """Bounded, deterministic corpus-derived proposals (byte-level mutation).

    Only suggests inputs; execution/adoption is decided elsewhere.  Works on
    arbitrary byte corpora so the same provider serves source, binary and
    archive-target drives.
    """

    def propose(
        self,
        corpus: list[bytes],
        plateau: PlateauSignal,
        *,
        seed: int,
        max_proposals: int = 8,
    ) -> list[bytes]:
        if not corpus:
            return []
        rng = random.Random(seed)
        proposals: list[bytes] = []
        base = corpus[: max(1, len(corpus))]
        for _ in range(max_proposals):
            item = bytearray(rng.choice(base))
            if not item:
                item = bytearray(b"\x00")
            mutation = rng.randrange(3)
            if mutation == 0:  # flip a byte
                idx = rng.randrange(len(item))
                item[idx] ^= 1 << rng.randrange(8)
            elif mutation == 1 and len(item) >= 2:  # splice two corpus items
                other = bytearray(rng.choice(base))
                cut = rng.randrange(min(len(item), len(other)) + 1)
                item = item[:cut] + other[cut : cut + rng.randrange(1, 8)]
            else:  # insert a dictionary byte
                pos = rng.randrange(len(item) + 1)
                item[pos:pos] = bytes([rng.randrange(1, 256)])
            if bytes(item) not in proposals:
                proposals.append(bytes(item))
            if len(proposals) >= max_proposals:
                break
        return proposals
