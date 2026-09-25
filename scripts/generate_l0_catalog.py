"""Generate the pinned L0 admission catalog from the self-authored benchmarks.

The L0 regression samples are the project's own vulnerable/clean Python
fixtures.  This script reads ``benchmarks/manifest.json``, fingerprints each
target tree, pins the current git commit and writes a version-locked intake
suite to ``benchmarks/catalog/l0_regression.yaml``.  Re-run it whenever the
L0 fixtures change; never hand-edit the hashes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import yaml

from vulnagent.intake.hashing import fingerprint_target

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_MANIFEST = REPO_ROOT / "benchmarks" / "manifest.json"
OUTPUT = REPO_ROOT / "benchmarks" / "catalog" / "l0_regression.yaml"


def _git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--short=12", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def build_catalog() -> dict:
    """Build the L0 suite dictionary with real fingerprints."""

    source = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
    revision = _git_head()
    samples = []
    for item in source["samples"]:
        target = REPO_ROOT / item["path"]
        samples.append(
            {
                "sample_id": item["sample_id"],
                "family_id": item.get("family_id"),
                "dataset": "l0_regression",
                "source_name": item.get("source", "VulnAgent self-authored"),
                "role": "train",
                "target_kind": item.get("target_type", "source"),
                "language": item.get("language"),
                "revision": revision,
                "target_path": item["path"],
                "target_sha256": fingerprint_target(target),
                "license_record": item.get("license", "Project educational use"),
                "authorization": {
                    "statement": item.get(
                        "authorization",
                        "local self-authored fixture; static analysis only",
                    ),
                    "static_read": True,
                    "file_transform": False,
                    "dynamic_run": False,
                    "data_export": False,
                },
                "time_budget_seconds": 300,
                "memory_budget_mb": 2048,
            }
        )
    return {
        "schema_version": 1,
        "suite_id": "l0-regression",
        "dataset": "l0_regression",
        "description": (
            "Pinned L0 regression catalog: self-authored vulnerable/clean "
            "Python fixtures used for fast regression and demos, not for "
            "claims about generalization."
        ),
        "pinned_revision": revision,
        "samples": samples,
    }


def write_catalog(output: Path) -> None:
    """Write the catalog atomically."""

    output.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(build_catalog(), sort_keys=False, allow_unicode=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    write_catalog(args.output)
    print(f"L0 catalog written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
