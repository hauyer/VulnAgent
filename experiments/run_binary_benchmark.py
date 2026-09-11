"""Compile self-authored C fixtures and run the canonical binary pipeline."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import logging
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from experiments.run_metrics import calculate_metrics, write_metrics
from vulnagent.bootstrap import build_v03_source_application
from vulnagent.contracts import Target, TargetType, TaskStatus, VulnerabilityStatus
from vulnagent.settings import Settings


LOGGER = logging.getLogger(__name__)
_REQUIRED_FIELDS = frozenset(
    {
        "sample_id",
        "path",
        "source",
        "language",
        "target_type",
        "ground_truth",
        "cwe",
        "expected_findings",
        "authorization",
        "run_command",
    }
)
_COMPILATION_PROFILES = (
    ("vulnagent_binary_symbol_rich", False, "symbol-rich"),
    ("vulnagent_binary_stripped", True, "stripped"),
)


def load_manifest(path: Path) -> dict[str, Any]:
    """Validate the binary source manifest before compiling anything."""
    manifest = json.loads(path.read_text(encoding="utf-8"))
    samples = manifest.get("samples") if isinstance(manifest, dict) else None
    if not isinstance(samples, list) or not samples:
        raise ValueError("binary benchmark manifest must contain samples")
    identifiers: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise ValueError(f"sample {index} must be an object")
        missing = sorted(_REQUIRED_FIELDS.difference(sample))
        if missing:
            raise ValueError(f"sample {index} is missing fields: {', '.join(missing)}")
        sample_id = str(sample["sample_id"])
        if not sample_id or sample_id in identifiers:
            raise ValueError(f"invalid or duplicate sample_id: {sample_id}")
        identifiers.add(sample_id)
        if sample["language"] != "c" or sample["target_type"] != "binary":
            raise ValueError(f"sample {sample_id} is not a C binary fixture")
        if sample["ground_truth"] not in {"vulnerable", "clean"}:
            raise ValueError(f"sample {sample_id} has invalid ground_truth")
    return manifest


def _resolve_source(root: Path, relative_path: str) -> Path:
    source = (root / relative_path).resolve()
    if not source.is_relative_to(root):
        raise ValueError(f"binary source escapes repository root: {relative_path}")
    if not source.is_file() or source.suffix.casefold() != ".c":
        raise FileNotFoundError(f"binary source is not a C file: {source}")
    return source


def _compiler() -> str:
    compiler = shutil.which("gcc") or shutil.which("cc")
    if compiler is None:
        raise RuntimeError("a local gcc/cc compiler is required for this benchmark")
    return compiler


def _compile(
    source: Path,
    output: Path,
    compiler: str,
    *,
    strip_symbols: bool,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [compiler, "-O0", "-fno-builtin"]
    if strip_symbols:
        command.append("-s")
    command.extend([str(source), "-o", str(output)])
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        error = completed.stderr.decode(errors="replace")[:2000]
        raise RuntimeError(f"compiler failed for {source.name}: {error}")


async def run_suite(
    manifest_path: Path,
    output_dir: Path,
    *,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Build each fixture and run Reverse→Logic/Obfuscation→Verification."""
    manifest = load_manifest(manifest_path)
    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    compiler = _compiler()
    binary_dir = output_dir / "compiled"
    suffix = ".exe" if platform.system() == "Windows" else ".bin"
    rows: list[dict[str, Any]] = []

    for method, strip_symbols, symbol_profile in _COMPILATION_PROFILES:
        for sample in manifest["samples"]:
            source = _resolve_source(root, str(sample["path"]))
            binary = (
                binary_dir / f"{sample['sample_id']}-{symbol_profile}{suffix}"
            ).resolve()
            _compile(
                source,
                binary,
                compiler,
                strip_symbols=strip_symbols,
            )
            services = build_v03_source_application(
                settings=Settings(vulnagent_profile="v03-source")
            )
            task = services.task_manager.create_task(
                Target(
                    target_id=f"{sample['sample_id']}-{symbol_profile}",
                    path=str(binary),
                    target_type=TargetType.BINARY,
                    language="c",
                    metadata={
                        "benchmark_source": str(source),
                        "symbol_profile": symbol_profile,
                    },
                )
            )
            started = perf_counter()
            context = await services.orchestrator.run(task.task_id)
            elapsed = perf_counter() - started
            if context.task.status is not TaskStatus.COMPLETED:
                raise RuntimeError(f"binary task failed: {context.task.error}")
            feature_message = next(
                (
                    item
                    for item in context.messages
                    if item.sender == "binary_analysis"
                    and "feature_analysis" in item.payload
                ),
                None,
            )
            feature_analysis = (
                feature_message.payload["feature_analysis"]
                if feature_message
                else {}
            )
            evidence_ids = {item.evidence_id for item in context.evidence}
            evidence_complete = (
                all(
                    finding.evidence_ids
                    and set(finding.evidence_ids).issubset(evidence_ids)
                    for finding in context.findings
                )
                if context.findings
                else True
            )
            rows.append(
                {
                    "sample_id": sample["sample_id"],
                    "family_id": sample.get("family_id"),
                    "difficulty": sample.get("difficulty"),
                    "method": method,
                    "symbol_profile": symbol_profile,
                    "expected": sample["ground_truth"],
                    "observed": "vulnerable" if context.findings else "clean",
                    "duration_seconds": elapsed,
                    "agent_steps": context.task.metadata.get("termination", {}).get(
                        "agent_steps_executed"
                    ),
                    "token_cost": None,
                    "coverage": None,
                    "crashes": 0,
                    "unique_crashes": 0,
                    "confirmed_findings": sum(
                        item.status is VulnerabilityStatus.CONFIRMED
                        for item in context.findings
                    ),
                    "uncertain_findings": sum(
                        item.status is VulnerabilityStatus.UNCERTAIN
                        for item in context.findings
                    ),
                    "rejected_findings": sum(
                        item.status is VulnerabilityStatus.REJECTED
                        for item in context.findings
                    ),
                    "evidence_complete": evidence_complete,
                    "finding_types": sorted(
                        {item.vulnerability_type for item in context.findings}
                    ),
                    "matched_symbols": sorted(
                        {
                            str(symbol)
                            for item in context.findings
                            for symbol in item.metadata.get("matched_symbols", [])
                        }
                    ),
                    "signal_bases": sorted(
                        {
                            str(item.metadata.get("signal_basis"))
                            for item in context.findings
                            if item.metadata.get("signal_basis")
                        }
                    ),
                    "semantic_callsite_count": sum(
                        int(item.metadata.get("semantic_callsite_count", 0))
                        for item in context.findings
                    ),
                    "logic_summary": feature_analysis.get("logic", {}).get(
                        "summary", {}
                    ),
                    "obfuscation_score": feature_analysis.get(
                        "obfuscation", {}
                    ).get("score", 0),
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "target_executed": False,
                }
            )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Run VulnAgent binary benchmark.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    output_dir = args.output_dir.resolve()
    manifest_path = args.manifest.resolve()
    rows = asyncio.run(run_suite(manifest_path, output_dir))
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "labelled_results.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    write_metrics(calculate_metrics(rows), output_dir)
    provenance = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "suite_id": load_manifest(manifest_path).get("suite_id"),
        "manifest_path": str(manifest_path),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "fixture_count": len(load_manifest(manifest_path)["samples"]),
        "family_count": len(
            {
                str(sample.get("family_id"))
                for sample in load_manifest(manifest_path)["samples"]
                if sample.get("family_id")
            }
        ),
        "difficulty_counts": {
            difficulty: sum(
                sample.get("difficulty") == difficulty
                for sample in load_manifest(manifest_path)["samples"]
            )
            for difficulty in ("basic", "hard")
        },
        "row_count": len(rows),
        "methods": [item[0] for item in _COMPILATION_PROFILES],
        "compiler": _compiler(),
        "callsite_decoder": _optional_package("capstone"),
        "python": platform.python_version(),
        "target_execution": False,
    }
    (output_dir / "run_manifest.json").write_text(
        json.dumps(provenance, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    LOGGER.info("Completed %d binary samples in %s", len(rows), output_dir)


def _optional_package(name: str) -> dict[str, Any]:
    """Record whether an optional experiment dependency was observable."""
    try:
        version = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return {"name": name, "available": False, "version": None}
    return {"name": name, "available": True, "version": version}


if __name__ == "__main__":
    main()
