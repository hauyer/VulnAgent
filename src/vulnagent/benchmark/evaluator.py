"""S1: independent blind evaluator (corrected counting semantics).

Consumes raw candidate rows (the discovery pipeline's own output) plus the
hidden ground-truth directory that the running Agent never sees, and
recomputes metrics with honest denominators:

* **Clustering first.**  Candidate rows carrying a ``root_cause_cluster``
  (the triage key from :mod:`vulnagent.benchmark.discovery_ports`) are
  collapsed into unique root-cause candidates *before* any matching, so 27
  crash inputs for one fault become one candidate (``raw_crashes`` is
  reported separately).
* **One-to-one matching.**  Each ground-truth record and each unique
  candidate matches at most once; every unmatched unique candidate is an FP,
  every unmatched GT is an FN.  A candidate is only ever matched to one GT.
* **Honest match basis.**  Matches are graded ``exact_location`` /
  ``same_file`` / ``type_only`` and the localization error is reported
  separately.  The default ``match_policy="strict"`` requires a location
  basis (a type-only candidate is an explicit FP + FN, never a silent TP);
  ``match_policy="type_only_allowed"`` counts type-only matches as TP
  (custom-discovery analysis view) and both views are available.
* **Full denominator.**  ``all_case_ids`` (the frozen sample list from the
  run manifest) keeps clean cases with no candidates in ``total_targets`` as
  ``tn`` rows instead of silently dropping them; precision/recall are only
  defined over evaluable units and stay ``None`` when the denominator is 0.
* **Dataset from manifest.**  ``CaseOutcome.dataset`` is mapped from the
  frozen ``BlindCaseManifest`` files (``manifest_dir``), never hard-coded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from vulnagent.benchmark.schema import (
    BlindCaseManifest,
    CaseOutcome,
    CaseRunStatus,
    DatasetName,
    EvaluationResult,
    GroundTruth,
    MatchBasis,
    Role,
)

_CANDIDATE_KEYS = ("case_id", "vulnerability_type", "cwe_id", "location")


@dataclass(slots=True)
class BlindEvaluator:
    """Recomputes blind-evaluation metrics from raw rows and hidden labels."""

    def _load_ground_truth(self, gt_dir: Path) -> dict[str, list[GroundTruth]]:
        records: dict[str, list[GroundTruth]] = {}
        for path in sorted(gt_dir.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            gt = GroundTruth.model_validate(raw)
            records.setdefault(gt.case_id, []).append(gt)
        return records

    def _load_manifests(
        self, manifest_dir: Path | None
    ) -> dict[str, BlindCaseManifest]:
        if manifest_dir is None:
            return {}
        by_case: dict[str, BlindCaseManifest] = {}
        for path in sorted(manifest_dir.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                manifest = BlindCaseManifest.model_validate(raw)
            except Exception:
                continue
            by_case.setdefault(manifest.case_id, manifest)
        return by_case

    @staticmethod
    def _status_of(candidate: dict) -> CaseRunStatus:
        raw = str(candidate.get("status", "")).lower()
        if raw in {"unsupported", "timeout", "unavailable", "invalid"}:
            return CaseRunStatus(raw)
        return CaseRunStatus.SUCCESS

    @staticmethod
    def _type_hit(candidate: dict, gt: GroundTruth) -> bool:
        """CWE or vulnerability-type overlap between candidate and GT."""
        cand_type = str(candidate.get("vulnerability_type", "")).lower()
        cand_cwe = str(candidate.get("cwe_id", "")).lower()
        gt_type = gt.vulnerability_type.lower()
        gt_cwe = gt.cwe_id.lower()
        return bool(
            (gt_cwe and gt_cwe in cand_cwe)
            or (gt_type and gt_type in cand_type)
            or (cand_type and cand_type in gt_type)
        )

    @classmethod
    def _match_basis(cls, candidate: dict, gt: GroundTruth) -> MatchBasis:
        """Grade the localization basis of a type-matched candidate."""
        cand_loc = str(candidate.get("location", ""))
        gt_loc = gt.location or ""
        if not cand_loc:
            return MatchBasis.TYPE_ONLY
        cand_file, _, cand_line = cand_loc.rpartition(":")
        gt_file, _, gt_line = gt_loc.rpartition(":")
        if cand_file == gt_file:
            if gt_line and gt_line != "0" and cand_line == gt_line:
                return MatchBasis.EXACT_LOCATION
            return MatchBasis.SAME_FILE
        return MatchBasis.TYPE_ONLY

    @staticmethod
    def _location_error(candidate: dict, gt: GroundTruth) -> float:
        """Normalized localization error: 0 exact, 1 completely off."""
        cand_loc = str(candidate.get("location", ""))
        gt_loc = gt.location or ""
        if not cand_loc or not gt_loc:
            return 1.0
        try:
            cand_file, cand_line = cand_loc.rsplit(":", 1)
            gt_file, gt_line = gt_loc.rsplit(":", 1)
        except ValueError:
            return 1.0
        if cand_file != gt_file:
            return 1.0
        if gt_line == "0":
            # Ground truth with unknown line: same file counts as a hit.
            return 0.0
        if not cand_line.isdigit() or not gt_line.isdigit():
            return 1.0
        delta = abs(int(cand_line) - int(gt_line))
        return min(delta / 10.0, 1.0)

    def _unique_candidates(
        self, rows: list[dict]
    ) -> list[dict]:
        """Collapse rows by root-cause cluster into unique candidates.

        Rows sharing a ``root_cause_cluster`` are produced by one triage pass
        and each carries the cluster's total raw crash count; the group keeps
        the maximum count (never double-counts a cluster).  Rows without a
        cluster key stay independent (one candidate per row).
        """
        unique: dict[str, dict] = {}
        for row in rows:
            if self._status_of(row) is not CaseRunStatus.SUCCESS:
                continue
            cluster = str(row.get("root_cause_cluster") or "")
            key = cluster if cluster else f"__row__:{row.get('candidate_id', id(row))}"
            existing = unique.get(key)
            if existing is None:
                unique[key] = dict(row)
                existing = unique[key]
                existing["raw_crash_count"] = int(row.get("raw_crash_count", 1))
            else:
                existing["raw_crash_count"] = max(
                    int(existing.get("raw_crash_count", 1)),
                    int(row.get("raw_crash_count", 1)),
                )
        return list(unique.values())

    def evaluate(
        self,
        candidates_path: Path,
        gt_dir: Path,
        *,
        run_id: str = "blind-eval",
        all_case_ids: Iterable[str] | None = None,
        manifest_dir: Path | None = None,
        match_policy: str = "strict",
    ) -> EvaluationResult:
        records = self._load_ground_truth(gt_dir)
        manifests = self._load_manifests(manifest_dir)

        rows_by_case: dict[str, list[dict]] = {}
        # Candidate rows written by the discovery process carry the
        # de-identified opaque_case_id (the agent workspace never sees the
        # dataset id); remap through the frozen manifests so they join the
        # ground-truth case.
        opaque_to_case = {
            m.opaque_case_id: m.case_id
            for m in manifests.values()
            if m.opaque_case_id
        }
        for line in Path(candidates_path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            case_id = row.get("case_id")
            if not case_id:
                continue
            case_id = opaque_to_case.get(case_id, case_id)
            rows_by_case.setdefault(case_id, []).append(row)

        all_ids = set(all_case_ids or ()) | set(records) | set(rows_by_case)
        case_ids = sorted(all_ids)
        outcomes: list[CaseOutcome] = []
        excluded: list[str] = []
        tp = fp = fn = 0
        case_tp = case_fp = case_fn = case_tn = 0
        loc_errors: list[float] = []
        evaluable = 0

        def dataset_of(case_id: str) -> DatasetName:
            manifest = manifests.get(case_id)
            return manifest.dataset if manifest is not None else DatasetName.SELF

        for case_id in case_ids:
            gts = records.get(case_id, [])
            rows = rows_by_case.get(case_id, [])
            dataset = dataset_of(case_id)

            # Clean case with no GT and no candidate rows: never silently
            # dropped, never counted as a finding; precision/recall stay
            # undefined over it (denominator only).
            if not gts and not rows:
                outcomes.append(
                    CaseOutcome(
                        case_id=case_id,
                        dataset=dataset,
                        role=Role.DEV,
                        status=CaseRunStatus.SUCCESS,
                        tn=True,
                        note="no ground truth and no candidate rows",
                    )
                )
                case_tn += 1
                continue

            # Labeled case with no candidate rows at all: a missed detection
            # (FN), never an invalid/excluded row.
            if gts and not rows:
                fn += len(gts)
                case_fn += 1
                evaluable += 1
                outcomes.append(
                    CaseOutcome(
                        case_id=case_id,
                        dataset=dataset,
                        role=Role.DEV,
                        status=CaseRunStatus.SUCCESS,
                        fn=True,
                        gt_count=len(gts),
                        note="ground truth present but no candidate rows",
                    )
                )
                continue

            status = self._status_of(rows[0]) if rows else CaseRunStatus.INVALID
            if status is not CaseRunStatus.SUCCESS:
                excluded.append(
                    f"{case_id}: {status.value} - "
                    f"{rows[0].get('note', '') if rows else 'no rows'}"
                )
                outcomes.append(
                    CaseOutcome(
                        case_id=case_id,
                        dataset=dataset,
                        role=Role.DEV,
                        status=status,
                        n_candidates=len(rows),
                        note=rows[0].get("note", "") if rows else "no rows",
                    )
                )
                continue

            if not gts:
                # Candidate(s) without ground truth: each unique candidate is
                # an FP; nothing is deleted.
                uniques = self._unique_candidates(rows)
                fp += len(uniques)
                case_fp += 1
                evaluable += 1
                outcomes.append(
                    CaseOutcome(
                        case_id=case_id,
                        dataset=dataset,
                        role=Role.DEV,
                        status=status,
                        fp=True,
                        n_candidates=len(uniques),
                        raw_crashes=sum(
                            int(r.get("raw_crash_count", 1)) for r in uniques
                        ),
                        note="candidate(s) without ground truth",
                    )
                )
                continue

            # Labeled case: collapse rows into unique root-cause candidates
            # first, then match each GT at most once and each candidate at
            # most once (best match basis wins).
            uniques = self._unique_candidates(rows)
            matched_gts: set[int] = set()
            matched_cands: set[int] = set()
            case_loc = 1.0
            case_basis = MatchBasis.NONE

            if not uniques:
                fn += len(gts)
                case_fn += 1
                evaluable += 1
                outcomes.append(
                    CaseOutcome(
                        case_id=case_id,
                        dataset=dataset,
                        role=Role.DEV,
                        status=status,
                        fn=True,
                        gt_count=len(gts),
                        note="ground truth present but no candidate rows",
                    )
                )
                continue

            rank = {
                MatchBasis.EXACT_LOCATION: 3,
                MatchBasis.SAME_FILE: 2,
                MatchBasis.TYPE_ONLY: 1,
                MatchBasis.NONE: 0,
            }
            for gt_idx, gt in enumerate(gts):
                best: tuple[int, int, MatchBasis, dict | None] = (
                    -1, -1, MatchBasis.NONE, None,
                )
                for cand_idx, cand in enumerate(uniques):
                    if cand_idx in matched_cands:
                        continue
                    if not self._type_hit(cand, gt):
                        continue
                    basis = self._match_basis(cand, gt)
                    if match_policy == "strict" and basis is MatchBasis.TYPE_ONLY:
                        continue
                    score = rank[basis]
                    if score > best[0]:
                        best = (score, cand_idx, basis, cand)
                if best[3] is not None:
                    matched_gts.add(gt_idx)
                    matched_cands.add(best[1])
                    loc = self._location_error(best[3], gt)
                    case_loc = min(case_loc, loc)
                    if rank[best[2]] > rank[case_basis]:
                        case_basis = best[2]

            case_tp_count = len(matched_gts)
            case_fp_count = len(uniques) - len(matched_cands)
            case_fn_count = len(gts) - len(matched_gts)
            tp += case_tp_count
            fp += case_fp_count
            fn += case_fn_count
            evaluable += 1
            if case_tp_count:
                case_tp += 1
                loc_errors.append(case_loc)
            else:
                case_fn += 1
            if case_fp_count:
                case_fp += 1
            outcomes.append(
                CaseOutcome(
                    case_id=case_id,
                    dataset=dataset,
                    role=Role.DEV,
                    status=status,
                    tp=case_tp_count > 0,
                    fp=case_fp_count > 0 and case_tp_count == 0,
                    fn=case_tp_count == 0 and case_fp_count == 0,
                    n_candidates=len(uniques),
                    raw_crashes=sum(
                        int(r.get("raw_crash_count", 1)) for r in uniques
                    ),
                    loc_error=case_loc if case_tp_count else None,
                    match_basis=case_basis,
                    gt_count=len(gts),
                    note=(
                        f"matched {case_tp_count}/{len(gts)} GT; "
                        f"{case_fp_count} unmatched candidate(s); "
                        f"basis={case_basis.value}"
                    ),
                )
            )

        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        avg_loc_error = sum(loc_errors) / len(loc_errors) if loc_errors else None
        case_precision = (
            case_tp / (case_tp + case_fp) if (case_tp + case_fp) else None
        )
        case_recall = (
            case_tp / (case_tp + case_fn) if (case_tp + case_fn) else None
        )

        return EvaluationResult(
            run_id=run_id,
            total_targets=len(case_ids),
            total_cases=len(case_ids),
            evaluable_cases=evaluable,
            excluded=excluded,
            tp=tp,
            fp=fp,
            fn=fn,
            precision=precision,
            recall=recall,
            case_tp=case_tp,
            case_fp=case_fp,
            case_fn=case_fn,
            case_tn=case_tn,
            case_precision=case_precision,
            case_recall=case_recall,
            avg_loc_error=avg_loc_error,
            match_policy=match_policy,
            per_case=outcomes,
        )
