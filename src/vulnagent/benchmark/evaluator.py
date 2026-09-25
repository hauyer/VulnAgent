"""WP5: independent blind evaluator.

Consumes raw candidate rows (the discovery pipeline's own output) plus the
hidden ground-truth directory that the running Agent never sees, and
recomputes TP/FP/FN, precision/recall and localization error. Every case --
including unsupported/timeout/unavailable/invalid -- stays in the original
denominator and is classified explicitly; nothing is silently deleted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml

from vulnagent.benchmark.schema import (
    CaseOutcome,
    CaseRunStatus,
    DatasetName,
    EvaluationResult,
    GroundTruth,
    Role,
)

_CANDIDATE_KEYS = ("case_id", "vulnerability_type", "cwe_id", "location")


@dataclass(slots=True)
class BlindEvaluator:
    """Recomputes blind-evaluation metrics from raw rows and hidden labels."""

    def _load_ground_truth(self, gt_dir: Path) -> dict[str, GroundTruth]:
        records: dict[str, GroundTruth] = {}
        for path in sorted(gt_dir.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            gt = GroundTruth.model_validate(raw)
            records[gt.case_id] = gt
        return records

    def _status_of(self, candidate: dict) -> CaseRunStatus:
        raw = str(candidate.get("status", "")).lower()
        if raw in {"unsupported", "timeout", "unavailable", "invalid"}:
            return CaseRunStatus(raw)
        return CaseRunStatus.SUCCESS

    def _matches(self, candidate: dict, gt: GroundTruth) -> tuple[bool, float]:
        """Type match plus location match -> (matched, loc_error 0..1)."""
        cand_type = str(candidate.get("vulnerability_type", "")).lower()
        cand_cwe = str(candidate.get("cwe_id", "")).lower()
        cand_loc = str(candidate.get("location", ""))
        gt_type = gt.vulnerability_type.lower()
        gt_cwe = gt.cwe_id.lower()

        type_hit = bool(
            (gt_cwe and gt_cwe in cand_cwe)
            or (gt_type and gt_type in cand_type)
            or (cand_type and cand_type in gt_type)
        )

        loc_error = self._location_error(cand_loc, gt.location)
        return type_hit and loc_error <= 0.5, loc_error

    @staticmethod
    def _location_error(cand_loc: str, gt_loc: str) -> float:
        """Normalized localization error: 0 exact, 1 completely off.

        Exact file:line match -> 0.0; same file -> small delta from line
        distance; different file -> 1.0.
        """
        if not cand_loc or not gt_loc:
            return 1.0
        try:
            cand_file, cand_line = cand_loc.rsplit(":", 1)
            gt_file, gt_line = gt_loc.rsplit(":", 1)
        except ValueError:
            return 1.0
        if cand_file != gt_file:
            return 1.0
        delta = abs(int(cand_line) - int(gt_line))
        return min(delta / 10.0, 1.0)

    def evaluate(
        self,
        candidates_path: Path,
        gt_dir: Path,
        *,
        run_id: str = "blind-eval",
    ) -> EvaluationResult:
        records = self._load_ground_truth(gt_dir)
        candidates_by_case: dict[str, list[dict]] = {}
        for line in Path(candidates_path).read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            case_id = row.get("case_id")
            if not case_id:
                continue
            candidates_by_case.setdefault(case_id, []).append(row)

        case_ids = sorted(
            {c for c in records} | {c for c in candidates_by_case}
        )
        outcomes: list[CaseOutcome] = []
        excluded: list[str] = []
        tp = fp = fn = 0
        loc_errors: list[float] = []
        evaluable = 0

        for case_id in case_ids:
            gt = records.get(case_id)
            rows = candidates_by_case.get(case_id, [])

            if not rows and gt is not None:
                # A labeled case with no candidate rows is a missed detection
                # (FN), never silently dropped.
                fn += 1
                evaluable += 1
                outcomes.append(
                    CaseOutcome(
                        case_id=case_id,
                        dataset=DatasetName.SELF,
                        role=Role.DEV,
                        status=CaseRunStatus.SUCCESS,
                        fn=True,
                        note="no candidate rows",
                    )
                )
                continue

            status = self._status_of(rows[0]) if rows else CaseRunStatus.INVALID

            if status is not CaseRunStatus.SUCCESS:
                excluded.append(
                    f"{case_id}: {status.value} - {rows[0].get('note', '') if rows else 'no rows'}"
                )
                outcomes.append(
                    CaseOutcome(
                        case_id=case_id,
                        dataset=DatasetName.SELF,
                        role=Role.DEV,
                        status=status,
                        n_candidates=len(rows),
                        note=rows[0].get("note", "") if rows else "no rows",
                    )
                )
                continue

            if gt is None:
                # Candidate without ground truth: FP with a note, never deleted.
                fp += len(rows)
                evaluable += 1
                outcomes.append(
                    CaseOutcome(
                        case_id=case_id,
                        dataset=DatasetName.SELF,
                        role=Role.DEV,
                        status=status,
                        fp=True,
                        n_candidates=len(rows),
                        note="candidate without ground truth",
                    )
                )
                continue

            evaluable += 1
            matched = False
            case_loc = 1.0
            case_fp = 0
            for row in rows:
                hit, loc = self._matches(row, gt)
                case_loc = min(case_loc, loc)
                if hit:
                    matched = True
                else:
                    case_fp += 1

            if matched:
                tp += 1
                loc_errors.append(case_loc)
            else:
                fn += 1
                fp += case_fp
            outcomes.append(
                CaseOutcome(
                    case_id=case_id,
                    dataset=DatasetName.SELF,
                    role=Role.DEV,
                    status=status,
                    tp=matched,
                    fn=not matched and not case_fp,
                    fp=bool(case_fp) and not matched,
                    n_candidates=len(rows),
                    loc_error=case_loc if matched else None,
                )
            )

        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        avg_loc_error = sum(loc_errors) / len(loc_errors) if loc_errors else None

        return EvaluationResult(
            run_id=run_id,
            total_cases=len(case_ids),
            evaluable_cases=evaluable,
            excluded=excluded,
            tp=tp,
            fp=fp,
            fn=fn,
            precision=precision,
            recall=recall,
            avg_loc_error=avg_loc_error,
            per_case=outcomes,
        )
