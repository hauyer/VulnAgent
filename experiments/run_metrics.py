"""Reproducibly compute benchmark and ablation metrics from labelled JSON rows.

Usage: python experiments/run_metrics.py input.json --output-dir results/run-001
Each input row needs ``method``, ``expected`` and ``observed`` values of either
``vulnerable`` or ``clean``. Optional ``duration_seconds`` and
``evidence_complete`` fields add operational and evidence-chain metrics.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def calculate_metrics(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row["method"])].append(row)

    results: list[dict[str, Any]] = []
    for method, group in sorted(groups.items()):
        true_positive = sum(row["expected"] == "vulnerable" and row["observed"] == "vulnerable" for row in group)
        false_positive = sum(row["expected"] == "clean" and row["observed"] == "vulnerable" for row in group)
        false_negative = sum(row["expected"] == "vulnerable" and row["observed"] == "clean" for row in group)
        true_negative = sum(row["expected"] == "clean" and row["observed"] == "clean" for row in group)
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
        results.append({
            "method": method,
            "samples": len(group),
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "false_positive_rate": false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0,
            "evidence_chain_coverage": sum(bool(row.get("evidence_complete")) for row in group) / len(group),
            "mean_duration_seconds": sum(float(row.get("duration_seconds", 0)) for row in group) / len(group),
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Calculate VulnAgent experiment metrics.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    rows = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise SystemExit("Input must be a JSON list of labelled experiment rows.")
    metrics = calculate_metrics(rows)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    with (args.output_dir / "metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(metrics[0]) if metrics else ["method"])
        writer.writeheader()
        writer.writerows(metrics)


if __name__ == "__main__":
    main()
