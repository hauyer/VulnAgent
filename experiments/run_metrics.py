"""Reproducibly compute benchmark and ablation metrics from labelled rows.

The runner accepts JSON arrays and JSON Lines. Besides classification metrics,
it records the operational signals needed by VulnAgent experiments: evidence
coverage, agent steps, token cost, coverage and crash counts. Precision and
recall include Wilson 95% intervals so small teaching benchmarks do not imply
false certainty.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from collections import defaultdict
from datetime import datetime, timezone
from math import sqrt
from pathlib import Path
from typing import Any


_LABELS = frozenset({"vulnerable", "clean"})


def validate_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate and defensively copy labelled experiment rows."""
    validated: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"row {index} must be an object")
        method = row.get("method")
        expected = row.get("expected")
        observed = row.get("observed")
        if not isinstance(method, str) or not method.strip():
            raise ValueError(f"row {index} has no non-empty method")
        if expected not in _LABELS:
            raise ValueError(f"row {index} has invalid expected label {expected!r}")
        if observed not in _LABELS:
            raise ValueError(f"row {index} has invalid observed label {observed!r}")
        validated.append(dict(row))
    return validated


def _mean_numeric(rows: list[dict[str, Any]], field: str) -> float | None:
    values: list[float] = []
    for row in rows:
        value = row.get(field)
        if value is None or isinstance(value, bool):
            continue
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            continue
    return sum(values) / len(values) if values else None


def _sum_numeric(rows: list[dict[str, Any]], field: str) -> float | int | None:
    values: list[float | int] = []
    for row in rows:
        value = row.get(field)
        if value is None or isinstance(value, bool):
            continue
        if isinstance(value, int):
            values.append(value)
        else:
            try:
                values.append(float(value))
            except (TypeError, ValueError):
                continue
    return sum(values) if values else None


def _single_text(rows: list[dict[str, Any]], field: str) -> str | None:
    values = {str(row[field]) for row in rows if row.get(field)}
    return next(iter(values)) if len(values) == 1 else None


def _wilson_interval(successes: int, total: int) -> tuple[float, float]:
    """Return a Wilson score interval with z=1.96 (approximately 95%)."""
    if total <= 0:
        return 0.0, 0.0
    z = 1.96
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * sqrt((proportion * (1 - proportion) + z * z / (4 * total)) / total)
        / denominator
    )
    return max(0.0, centre - margin), min(1.0, centre + margin)


def _unique_crash_count(rows: list[dict[str, Any]]) -> int:
    """Count global fingerprints when available, otherwise use row counts."""
    fingerprints: set[str] = set()
    has_fingerprints = False
    for row in rows:
        values = row.get("crash_fingerprints")
        if not isinstance(values, list):
            continue
        has_fingerprints = True
        fingerprints.update(str(item) for item in values if item)
    if has_fingerprints:
        return len(fingerprints)
    return sum(int(row.get("unique_crashes", 0)) for row in rows)


def calculate_metrics(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate validated rows by method without inventing missing values."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in validate_rows(rows):
        groups[str(row["method"])].append(row)

    results: list[dict[str, Any]] = []
    for method, group in sorted(groups.items()):
        true_positive = sum(row["expected"] == "vulnerable" and row["observed"] == "vulnerable" for row in group)
        false_positive = sum(row["expected"] == "clean" and row["observed"] == "vulnerable" for row in group)
        false_negative = sum(row["expected"] == "vulnerable" and row["observed"] == "clean" for row in group)
        true_negative = sum(row["expected"] == "clean" and row["observed"] == "clean" for row in group)
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
        precision_low, precision_high = _wilson_interval(
            true_positive,
            true_positive + false_positive,
        )
        recall_low, recall_high = _wilson_interval(
            true_positive,
            true_positive + false_negative,
        )
        results.append({
            "method": method,
            "samples": len(group),
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
            "precision": precision,
            "precision_ci95_low": precision_low,
            "precision_ci95_high": precision_high,
            "recall": recall,
            "recall_ci95_low": recall_low,
            "recall_ci95_high": recall_high,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "false_positive_rate": false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0,
            "evidence_chain_coverage": sum(bool(row.get("evidence_complete")) for row in group) / len(group),
            "mean_duration_seconds": _mean_numeric(group, "duration_seconds"),
            "mean_agent_steps": _mean_numeric(group, "agent_steps"),
            "mean_token_cost": _mean_numeric(group, "token_cost"),
            "total_token_cost": _sum_numeric(group, "token_cost"),
            "token_cost_currency": _single_text(group, "token_cost_currency"),
            "usage_available_count": sum(bool(row.get("usage_available")) for row in group),
            "prompt_tokens": _sum_numeric(group, "prompt_tokens"),
            "completion_tokens": _sum_numeric(group, "completion_tokens"),
            "total_tokens": _sum_numeric(group, "total_tokens"),
            "cached_prompt_tokens": _sum_numeric(group, "cached_prompt_tokens"),
            "mean_coverage": _mean_numeric(group, "coverage"),
            "confirmed_finding_count": sum(
                int(row.get("confirmed_findings", 0)) for row in group
            ),
            "uncertain_finding_count": sum(
                int(row.get("uncertain_findings", 0)) for row in group
            ),
            "crash_count": sum(int(row.get("crashes", 0)) for row in group),
            "unique_crash_count": _unique_crash_count(group),
        })
    return results


def load_rows(path: Path) -> list[dict[str, Any]]:
    """Load a JSON array or JSON Lines file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.casefold() in {".jsonl", ".ndjson"}:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        rows = json.loads(text)
    if not isinstance(rows, list):
        raise ValueError("input must be a JSON list or JSON Lines sequence")
    return validate_rows(rows)


def write_metrics(metrics: list[dict[str, Any]], output_dir: Path) -> None:
    """Write the canonical JSON and CSV metric artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    with (output_dir / "metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(metrics[0]) if metrics else ["method"],
        )
        writer.writeheader()
        writer.writerows(metrics)


def main() -> None:
    parser = argparse.ArgumentParser(description="Calculate VulnAgent experiment metrics.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        rows = load_rows(args.input)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"Invalid experiment input: {exc}") from exc
    metrics = calculate_metrics(rows)
    write_metrics(metrics, args.output_dir)
    digest = hashlib.sha256(args.input.read_bytes()).hexdigest()
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_path": str(args.input.resolve()),
        "input_sha256": digest,
        "row_count": len(rows),
        "methods": sorted({str(row["method"]) for row in rows}),
        "python": platform.python_version(),
        "command": [sys.executable, *sys.argv],
    }
    (args.output_dir / "run_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
