"""Compile authorized C fixtures as ELF and run the non-executing pipeline."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
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
_ZIG_ELF_TARGET = "x86_64-linux-gnu"
_REQUIRED_FIELDS = frozenset(
    {
        "sample_id",
        "family_id",
        "difficulty",
        "path",
        "source",
        "license",
        "language",
        "target_type",
        "expected_format",
        "ground_truth",
        "cwe",
        "expected_findings",
        "authorization",
    }
)
_PROFILES = (
    ("vulnagent_elf_symbol_rich", ("-O0", "-fno-builtin", "-no-pie"), "symbol-rich"),
    ("vulnagent_elf_stripped", ("-O0", "-fno-builtin", "-no-pie", "-s"), "stripped"),
    ("vulnagent_elf_pie", ("-O0", "-fno-builtin", "-fPIE", "-pie"), "pie"),
)


def render_summary(metrics: list[dict[str, Any]], provenance: dict[str, Any]) -> str:
    """Render a truthful, presentation-ready summary for the real ELF run."""

    lines = [
        "# VulnAgent V0.4 真实 ELF Benchmark",
        "",
        f"> 生成时间：{provenance['generated_at']}",
        f"> 工具链：Zig {provenance.get('compiler_version', 'unknown')} / "
        f"`{provenance.get('compiler_machine', 'unknown')}`",
        "> 全流程只读取生成的 ELF，未执行任何 ELF 目标。",
        "",
        "| Profile | 样本 | TP | FP | TN | FN | Precision | Recall | F1 | Evidence |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for metric in metrics:
        lines.append(
            "| {method} | {samples} | {tp} | {fp} | {tn} | {fn} | {precision:.3f} | "
            "{recall:.3f} | {f1:.3f} | {coverage:.3f} |".format(
                method=metric.get("method", "unknown"),
                samples=metric.get("samples", 0),
                tp=metric.get("true_positive", 0),
                fp=metric.get("false_positive", 0),
                tn=metric.get("true_negative", 0),
                fn=metric.get("false_negative", 0),
                precision=float(metric.get("precision", 0)),
                recall=float(metric.get("recall", 0)),
                f1=float(metric.get("f1", 0)),
                coverage=float(metric.get("evidence_chain_coverage", 0)),
            )
        )
    lines.extend(
        [
            "",
            "## 实验边界",
            "",
            f"- {provenance.get('fixture_count', 0)} 个自研授权 C Fixture，"
            f"{provenance.get('family_count', 0)} 个漏洞家族，3 种编译 Profile，共 "
            f"{provenance.get('row_count', 0)} 条分析记录。",
            "- Ground Truth 来自自研成对 Fixture，不代表真实世界总体分布。",
            "- 每个 Profile 只有 3 个正样本；即便 F1=1.0，95% Wilson 下界仍约为 0.438。",
            "- 所有 Finding 保持 `UNCERTAIN`，没有绕过独立 Verification 冒充确认漏洞。",
            "",
        ]
    )
    return "\n".join(lines)


def load_manifest(path: Path) -> dict[str, Any]:
    """Validate the ELF benchmark manifest before invoking a compiler."""
    manifest = json.loads(path.read_text(encoding="utf-8"))
    samples = manifest.get("samples") if isinstance(manifest, dict) else None
    if not isinstance(samples, list) or not samples:
        raise ValueError("ELF benchmark manifest must contain samples")
    identifiers: set[str] = set()
    families: dict[str, set[str]] = {}
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
        if (
            sample["language"] != "c"
            or sample["target_type"] != "binary"
            or sample["expected_format"] != "ELF"
        ):
            raise ValueError(f"sample {sample_id} is not a C ELF fixture")
        truth = str(sample["ground_truth"])
        if truth not in {"vulnerable", "clean"}:
            raise ValueError(f"sample {sample_id} has invalid ground_truth")
        families.setdefault(str(sample["family_id"]), set()).add(truth)
    if any(truths != {"vulnerable", "clean"} for truths in families.values()):
        raise ValueError("each ELF family must pair one vulnerable and one clean sample")
    return manifest


def _resolve_source(root: Path, relative_path: str) -> Path:
    source = (root / relative_path).resolve()
    if not source.is_relative_to(root):
        raise ValueError(f"ELF source escapes repository root: {relative_path}")
    if not source.is_file() or source.suffix.casefold() != ".c":
        raise FileNotFoundError(f"ELF source is not a C file: {source}")
    return source


def _compiler(requested: str | None = None) -> str:
    compiler = shutil.which(requested) if requested else (shutil.which("gcc") or shutil.which("cc"))
    if compiler is None:
        raise RuntimeError("a Linux-targeting gcc/cc compiler is required for the ELF benchmark")
    return compiler


def _compile_elf(source: Path, output: Path, compiler: str, flags: tuple[str, ...]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [*_compiler_prefix(compiler), *flags, str(source), "-o", str(output)]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=120 if _is_zig(compiler) else 30,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"ELF compiler timed out for {source.name}"
        ) from exc
    if completed.returncode != 0:
        error = completed.stderr.decode(errors="replace")[:2000]
        raise RuntimeError(f"ELF compiler failed for {source.name}: {error}")
    try:
        magic = output.read_bytes()[:4]
    except OSError as exc:
        raise RuntimeError(f"ELF compiler did not create {output.name}: {exc}") from exc
    if magic != b"\x7fELF":
        raise RuntimeError(
            "configured compiler did not produce ELF output; use Linux/WSL or an explicit cross-compiler"
        )


def _compiler_version(compiler: str) -> str | None:
    try:
        completed = subprocess.run(
            [compiler, "version"] if _is_zig(compiler) else [compiler, "--version"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    first_line = completed.stdout.decode(errors="replace").splitlines()
    return first_line[0][:256] if first_line else None


def _compiler_machine(compiler: str) -> str | None:
    """Return the compiler target triple when the driver exposes one."""

    if _is_zig(compiler):
        return _ZIG_ELF_TARGET
    try:
        completed = subprocess.run(
            [compiler, "-dumpmachine"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    target = completed.stdout.decode(errors="replace").strip().casefold()
    return target[:256] or None


def _require_elf_compiler(compiler: str) -> str | None:
    """Reject known Windows/Mach-O targets before creating benchmark output."""
    machine = _compiler_machine(compiler)
    if machine and any(marker in machine for marker in ("mingw", "windows", "msvc", "darwin")):
        raise RuntimeError(
            f"compiler target {machine!r} does not produce ELF; use Linux/WSL or an ELF cross-compiler"
        )
    return machine


def _is_zig(compiler: str) -> bool:
    return Path(compiler).stem.casefold() == "zig"


def _compiler_prefix(compiler: str) -> list[str]:
    """Return a compiler argv prefix, including Zig's explicit ELF target."""

    if _is_zig(compiler):
        return [compiler, "cc", "-target", _ZIG_ELF_TARGET]
    return [compiler]


async def run_suite(
    manifest_path: Path,
    output_dir: Path,
    *,
    repo_root: Path | None = None,
    compiler_name: str | None = None,
) -> list[dict[str, Any]]:
    """Compile three ELF profiles and analyze every target without executing it."""
    manifest = load_manifest(manifest_path)
    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    compiler = _compiler(compiler_name)
    _require_elf_compiler(compiler)
    binary_dir = output_dir / "compiled"
    rows: list[dict[str, Any]] = []

    for method, flags, profile_name in _PROFILES:
        for sample in manifest["samples"]:
            source = _resolve_source(root, str(sample["path"]))
            binary = (binary_dir / f"{sample['sample_id']}-{profile_name}.elf").resolve()
            _compile_elf(source, binary, compiler, flags)
            services = build_v03_source_application(
                settings=Settings(vulnagent_profile="v03-source")
            )
            task = services.task_manager.create_task(
                Target(
                    target_id=f"{sample['sample_id']}-{profile_name}",
                    path=str(binary),
                    target_type=TargetType.BINARY,
                    language="c",
                    metadata={"symbol_profile": profile_name, "expected_format": "ELF"},
                )
            )
            started = perf_counter()
            context = await services.orchestrator.run(task.task_id)
            elapsed = perf_counter() - started
            if context.task.status is not TaskStatus.COMPLETED:
                raise RuntimeError(f"ELF task failed: {context.task.error}")
            analysis_message = next(
                item
                for item in context.messages
                if item.sender == "binary_analysis" and "analysis" in item.payload
            )
            analysis = analysis_message.payload["analysis"]
            if analysis.get("file_format") != "ELF":
                raise RuntimeError(f"analyzer did not report ELF for {binary.name}")
            evidence_ids = {item.evidence_id for item in context.evidence}
            evidence_complete = all(
                finding.evidence_ids
                and set(finding.evidence_ids).issubset(evidence_ids)
                for finding in context.findings
            ) if context.findings else True
            rows.append(
                {
                    "sample_id": sample["sample_id"],
                    "family_id": sample["family_id"],
                    "difficulty": sample["difficulty"],
                    "method": method,
                    "symbol_profile": profile_name,
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
                    "evidence_complete": evidence_complete,
                    "matched_symbols": sorted(
                        {
                            str(symbol)
                            for item in context.findings
                            for symbol in item.metadata.get("matched_symbols", [])
                        }
                    ),
                    "file_format": analysis.get("file_format"),
                    "architecture": analysis.get("architecture"),
                    "elf_type": analysis.get("metadata", {}).get("format_details", {}).get(
                        "elf_type"
                    ),
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "target_executed": False,
                }
            )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the real Linux ELF benchmark.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--compiler")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    manifest_path = args.manifest.resolve()
    output_dir = args.output_dir.resolve()
    compiler = _compiler(args.compiler)
    try:
        compiler_machine = _require_elf_compiler(compiler)
        rows = asyncio.run(
            run_suite(
                manifest_path,
                output_dir,
                compiler_name=args.compiler,
            )
        )
    except RuntimeError as exc:
        LOGGER.error("%s", exc)
        raise SystemExit(2) from None
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "labelled_results.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    metrics = calculate_metrics(rows)
    write_metrics(metrics, output_dir)
    manifest = load_manifest(manifest_path)
    provenance = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "suite_id": manifest.get("suite_id"),
        "manifest_path": str(manifest_path),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "fixture_count": len(manifest["samples"]),
        "family_count": len({sample["family_id"] for sample in manifest["samples"]}),
        "row_count": len(rows),
        "profiles": [profile for _, _, profile in _PROFILES],
        "compiler": compiler,
        "compiler_command_prefix": _compiler_prefix(compiler),
        "compiler_version": _compiler_version(compiler),
        "compiler_machine": compiler_machine,
        "host_platform": platform.platform(),
        "python": platform.python_version(),
        "target_execution": False,
    }
    (output_dir / "run_manifest.json").write_text(
        json.dumps(provenance, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (output_dir / "summary.md").write_text(
        render_summary(metrics, provenance), encoding="utf-8"
    )
    LOGGER.info("Completed %d ELF analysis rows in %s", len(rows), output_dir)


if __name__ == "__main__":
    main()
