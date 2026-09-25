"""Candidate fusion engine (V0.5 / P4).

Normalizes ``VulnerabilityCandidate`` items from any number of engines into a
stable ``CandidateFingerprint`` and groups them into ``FusedCandidate`` items.
Fusion identity follows the blueprint (docs, section 15.1):

    CWE + normalized location + sink + function + taint source

Missing components degrade gracefully (empty placeholder) so two engines that
disagree on one attribute can still be matched on the rest; the fingerprint key
is deterministic and human-readable for review.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable

from vulnagent.contracts import (
    CandidateFingerprint,
    FusedCandidate,
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)

LINE_TOLERANCE = 3
_FS_SEP_RE = re.compile(r"[\\/]+")


def _norm_path(file_path: str | None, base_path: str | Path | None = None) -> str:
    if not file_path:
        return ""
    raw = str(file_path)
    if base_path is not None:
        try:
            relative = os.path.relpath(raw, str(base_path))
            if not relative.startswith(".."):
                return _FS_SEP_RE.sub("/", relative).lstrip("./")
        except ValueError:
            pass
    cleaned = _FS_SEP_RE.sub("/", raw).strip()
    return cleaned.lstrip("./")


def _line_bucket(line: int | None) -> int:
    """Collapse nearby lines (within LINE_TOLERANCE) into one bucket.

    1-based lines: line 1..3 -> bucket 0, line 4..6 -> bucket 3, ...
    """
    if line is None:
        return 0
    return int((line - 1) // LINE_TOLERANCE) * LINE_TOLERANCE


def _first_cwe(candidate: VulnerabilityCandidate) -> str | None:
    if candidate.cwe_id:
        return candidate.cwe_id
    metadata_cwe = (candidate.metadata or {}).get("cwe_id")
    return str(metadata_cwe) if metadata_cwe else None


def _sink_of(candidate: VulnerabilityCandidate) -> str | None:
    sink = (candidate.metadata or {}).get("sink")
    return str(sink) if sink else None


def _taint_source_of(candidate: VulnerabilityCandidate) -> str | None:
    kinds = (candidate.metadata or {}).get("source_kinds")
    if isinstance(kinds, list) and kinds:
        return str(kinds[0])
    if isinstance(kinds, str) and kinds:
        return kinds
    return None


def _function_of(candidate: VulnerabilityCandidate) -> str | None:
    location = candidate.location
    if location is None:
        return None
    return location.function_name or location.module_name or None


class CandidateNormalizer:
    """Extracts the fingerprint components from any candidate."""

    def fingerprint(
        self,
        candidate: VulnerabilityCandidate,
        base_path: str | Path | None = None,
    ) -> CandidateFingerprint:
        location = candidate.location
        norm_location = _norm_path(location.file_path if location else None, base_path)
        bucket = _line_bucket(location.line_start if location else None)
        normalized_location = f"{norm_location}@{bucket}" if norm_location else ""

        cwe = _first_cwe(candidate) or candidate.vulnerability_type
        sink = _sink_of(candidate)
        function = _function_of(candidate)
        taint_source = _taint_source_of(candidate)

        key = "|".join(
            part or ""
            for part in (cwe, normalized_location, sink, function, taint_source)
        )
        loose_key = "|".join(part or "" for part in (cwe, normalized_location, sink))
        return CandidateFingerprint(
            key=key,
            loose_key=loose_key,
            cwe_id=_first_cwe(candidate),
            vulnerability_type=candidate.vulnerability_type,
            normalized_location=normalized_location,
            sink=sink,
            function=function,
            taint_source=taint_source,
            components={
                "file_path": location.file_path if location else None,
                "line_start": location.line_start if location else None,
                "line_bucket": bucket,
                "module_name": location.module_name if location else None,
                "source_kinds": (candidate.metadata or {}).get("source_kinds"),
                "rule_id": (candidate.metadata or {}).get("rule_id"),
            },
        )


class CandidateFusionEngine:
    """Groups candidates by fingerprint into FusedCandidate items."""

    def __init__(self, normalizer: CandidateNormalizer | None = None) -> None:
        self._normalizer = normalizer or CandidateNormalizer()

    def fuse(
        self,
        candidates: Iterable[VulnerabilityCandidate],
        independence_groups: dict[str, str] | None = None,
        base_path: str | Path | None = None,
    ) -> list[FusedCandidate]:
        """Merge candidates; ``independence_groups`` maps candidate_id -> group.

        Grouping uses the loose key (CWE + normalized location + sink) so that
        engines with different function/taint-source extraction still converge
        on the same underlying flaw.  Strict keys are preserved per member for
        review.
        """
        groups = dict(independence_groups) if independence_groups else {}

        buckets: dict[str, list[VulnerabilityCandidate]] = {}
        strict_keys: dict[str, list[str]] = {}
        for candidate in candidates:
            fingerprint = self._normalizer.fingerprint(candidate, base_path)
            buckets.setdefault(fingerprint.loose_key, []).append(candidate)
            strict_keys.setdefault(fingerprint.loose_key, []).append(fingerprint.key)

        fused: list[FusedCandidate] = []
        for key, members in buckets.items():
            members.sort(key=lambda c: c.confidence, reverse=True)
            primary = members[0]
            source_ids = [c.vulnerability_id for c in members]
            independence = sorted(
                {groups.get(c.vulnerability_id, "") for c in members if groups.get(c.vulnerability_id)}
            )
            evidence_ids: list[str] = []
            for c in members:
                for evidence_id in c.evidence_ids:
                    if evidence_id not in evidence_ids:
                        evidence_ids.append(evidence_id)
            fused.append(
                FusedCandidate(
                    candidate_id=f"fused-{primary.vulnerability_id}",
                    task_id=primary.task_id,
                    vulnerability_type=primary.vulnerability_type,
                    cwe_id=primary.cwe_id,
                    primary_location=primary.location,
                    source_candidates=source_ids,
                    supporting_independence_groups=independence,
                    contradictions=[],
                    evidence_ids=evidence_ids,
                    fused_confidence=round(max(c.confidence for c in members), 3),
                    status=VulnerabilityStatus.CANDIDATE,
                    metadata={
                        "fingerprint_key": key,
                        "strict_keys": sorted(set(strict_keys.get(key, []))),
                        "member_count": len(members),
                        "member_producers": sorted(
                            {c.producer or c.source_agent for c in members}
                        ),
                    },
                )
            )
        fused.sort(key=lambda item: item.fused_confidence, reverse=True)
        return fused
