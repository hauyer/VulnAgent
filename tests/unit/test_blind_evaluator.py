"""WP5 unit: independent blind evaluator (TP/FP/FN, original denominator)."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from vulnagent.benchmark import BlindEvaluator

_GT_TPL = """schema_version: 1
case_id: {case_id}
vulnerability_type: {vtype}
cwe_id: {cwe}
title: t
description: d
location: {loc}
trigger_input: ""
fixed_commit: ""
patch_hint: ""
verified: true
"""


def _write_gt(gt_dir: Path, case_id: str, vtype: str, cwe: str, loc: str) -> None:
    gt_dir.mkdir(parents=True, exist_ok=True)
    (gt_dir / f"{case_id}.yaml").write_text(
        _GT_TPL.format(case_id=case_id, vtype=vtype, cwe=cwe, loc=loc),
        encoding="utf-8",
    )


def _write_candidates(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n"
    path.write_text(text, encoding="utf-8")


def test_evaluator_scores_tp_fp_fn(tmp_path: Path) -> None:
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir, "a", "stack-buffer-overflow", "CWE-121", "vuln.c:16")
    _write_gt(gt_dir, "b", "command-injection", "CWE-78", "app.py:10")
    _write_gt(gt_dir, "c", "use-after-free", "CWE-416", "obj.c:5")

    rows = [
        {"case_id": "a", "vulnerability_type": "stack-buffer-overflow",
         "cwe_id": "CWE-121", "location": "vuln.c:17", "status": "success"},
        {"case_id": "b", "vulnerability_type": "command-injection",
         "cwe_id": "CWE-78", "location": "app.py:11", "status": "success"},
        {"case_id": "x-extra", "vulnerability_type": "path-traversal",
         "cwe_id": "CWE-22", "location": "x.py:1", "status": "success"},
    ]
    cand_path = tmp_path / "candidates.jsonl"
    _write_candidates(cand_path, rows)

    result = BlindEvaluator().evaluate(cand_path, gt_dir, run_id="r")
    assert result.total_cases == 4  # 3 GT cases + 1 orphan candidate case
    assert result.tp == 2
    assert result.fn == 1  # case c has no candidate
    assert result.fp == 1  # orphan candidate x-extra
    assert result.precision == 2 / 3
    assert result.recall == 2 / 3


def test_evaluator_keeps_failed_cases_in_denominator(tmp_path: Path) -> None:
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir, "a", "x", "CWE-1", "a.py:1")
    _write_gt(gt_dir, "b", "y", "CWE-2", "b.py:1")
    _write_gt(gt_dir, "c", "z", "CWE-3", "c.py:1")

    rows = [
        {"case_id": "a", "status": "success", "vulnerability_type": "x",
         "cwe_id": "CWE-1", "location": "a.py:1", "note": "ok"},
        {"case_id": "b", "status": "unavailable",
         "note": "semgrep toolchain missing"},
        {"case_id": "c", "status": "timeout", "note": "exceeded budget"},
    ]
    cand_path = tmp_path / "candidates.jsonl"
    _write_candidates(cand_path, rows)

    result = BlindEvaluator().evaluate(cand_path, gt_dir, run_id="r")
    # Original denominator preserved; failures are explicit, not deleted.
    assert result.total_cases == 3
    assert result.evaluable_cases == 1
    assert result.tp == 1
    assert result.fn == 0
    assert len(result.excluded) == 2
    assert any("unavailable" in line for line in result.excluded)
    assert any("timeout" in line for line in result.excluded)


def test_evaluator_location_error(tmp_path: Path) -> None:
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir, "a", "x", "CWE-1", "a.py:10")

    rows = [
        {"case_id": "a", "vulnerability_type": "x", "cwe_id": "CWE-1",
         "location": "other.py:1", "status": "success"},
    ]
    cand_path = tmp_path / "candidates.jsonl"
    _write_candidates(cand_path, rows)

    result = BlindEvaluator().evaluate(cand_path, gt_dir, run_id="r")
    # Wrong file -> no match -> FN, not TP.
    assert result.tp == 0
    assert result.fn == 1


def test_evaluator_writes_metrics_json(tmp_path: Path) -> None:
    gt_dir = tmp_path / "gt"
    _write_gt(gt_dir, "a", "x", "CWE-1", "a.py:1")
    _write_candidates(
        tmp_path / "candidates.jsonl",
        [{"case_id": "a", "vulnerability_type": "x", "cwe_id": "CWE-1",
          "location": "a.py:1", "status": "success"}],
    )
    result = BlindEvaluator().evaluate(
        tmp_path / "candidates.jsonl", gt_dir, run_id="r"
    )
    metrics_path = tmp_path / "metrics.json"
    result.write_metrics(str(metrics_path))
    written = json.loads(metrics_path.read_text(encoding="utf-8"))
    assert written["tp"] == 1
    assert written["precision"] == 1.0
