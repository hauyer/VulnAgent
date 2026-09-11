"""Analyze authorized packed/obfuscated crackmes without executing targets.

The manifest is the provenance and authorization boundary.  Expected observations
are never sent to analyzers; they are retained only for post-analysis comparison.
Optional UPX/radare2 programs parse or transform files but never launch the target.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import platform
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Mapping

from experiments.audit_protected_samples import audit_manifests, load_manifest
from vulnagent.analyzers.binary.obfuscation import ObfuscationAnalyzer
from vulnagent.analyzers.binary.reverse import Radare2Adapter, UpxAdapter
from vulnagent.analyzers.binary.reverse.static import StaticBinaryReverseAnalyzer
from vulnagent.bootstrap import build_v03_source_application
from vulnagent.contracts import (
    BinaryAnalysisRequest,
    Target,
    TargetType,
    TaskStatus,
)
from vulnagent.report import write_report_html, write_report_pdf
from vulnagent.settings import Settings


LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_UPX = ROOT / "tools" / "upx" / "upx-5.2.1-win64" / "upx.exe"
DEFAULT_RADARE2 = (
    ROOT / "tools" / "radare2" / "radare2-6.2.2-w64" / "bin" / "radare2.exe"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False),
        encoding="utf-8",
    )
    temporary.replace(path)


def _write_text_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def _material_path(manifest_path: Path, sample: Mapping[str, Any]) -> Path:
    relative = Path(str(sample["local_path"]))
    if relative.is_absolute():
        raise ValueError(f"absolute protected sample path: {sample['sample_id']}")
    target = (manifest_path.parent / relative).resolve()
    materials = (manifest_path.parent / "materials").resolve()
    if not target.is_relative_to(materials) or not target.is_file():
        raise ValueError(f"protected sample is outside materials: {sample['sample_id']}")
    return target


def _tool_version(result: Any) -> dict[str, Any]:
    first_line = result.stdout.strip().splitlines()[:1] if result.stdout else []
    return {
        "status": result.status,
        "executed": result.executed,
        "version_line": first_line[0][:256] if first_line else None,
        "error": result.error,
    }


def _upx_summary(result: Any) -> dict[str, Any]:
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return {
        "status": result.status,
        "tool_process_executed": result.executed,
        "target_executed": False,
        "return_code": result.return_code,
        "facts": result.facts or {},
        "output_excerpt": lines[:8],
        "error": result.error,
        "truncated": result.truncated,
    }


def _radare_summary(result: Any) -> dict[str, Any]:
    facts = result.facts or {}
    functions = facts.get("functions", []) if isinstance(facts, Mapping) else []
    cfg = facts.get("cfg", {}) if isinstance(facts, Mapping) else {}
    pseudocode = facts.get("pseudocode", {}) if isinstance(facts, Mapping) else {}
    failures = facts.get("pseudocode_failures", []) if isinstance(facts, Mapping) else []
    safe_pseudocode = {
        str(address): str(code)[:4096]
        for address, code in list(pseudocode.items())[:8]
    } if isinstance(pseudocode, Mapping) else {}
    return {
        "status": result.status,
        "tool_process_executed": result.executed,
        "target_executed": False,
        "return_code": result.return_code,
        "function_count": len(functions) if isinstance(functions, list) else 0,
        "cfg_node_count": len(cfg) if isinstance(cfg, Mapping) else 0,
        "pseudocode_count": len(pseudocode) if isinstance(pseudocode, Mapping) else 0,
        "pseudocode": safe_pseudocode,
        "pseudocode_failures": failures[:8] if isinstance(failures, list) else [],
        "error": result.error,
        "truncated": result.truncated,
    }


async def _pipeline_result(
    sample: Mapping[str, Any],
    target: Path,
    report_dir: Path,
) -> dict[str, Any]:
    services = build_v03_source_application(
        settings=Settings(vulnagent_profile="v03-source")
    )
    task = services.task_manager.create_task(
        Target(
            target_id=str(sample["sample_id"]),
            path=str(target),
            target_type=TargetType.BINARY,
            metadata={
                "authorization": "non-commercial educational static analysis",
                "dynamic_execution": False,
                "protection_kind": sample["protection"]["kind"],
                "source_uri": sample["provenance"]["source_uri"],
            },
        )
    )
    started = perf_counter()
    context = await services.orchestrator.run(task.task_id)
    elapsed = perf_counter() - started
    if context.task.status is not TaskStatus.COMPLETED:
        raise RuntimeError(
            f"protected pipeline failed for {sample['sample_id']}: {context.task.error}"
        )
    report = context.reports[-1].content
    report_dir.mkdir(parents=True, exist_ok=True)
    report_json = report_dir / f"{sample['sample_id']}.json"
    report_html = report_dir / f"{sample['sample_id']}.html"
    report_pdf = report_dir / f"{sample['sample_id']}.pdf"
    _write_json_atomic(report_json, report)
    write_report_html(report, report_html)
    write_report_pdf(report, report_pdf, title=f"VulnAgent 受保护样本报告 — {sample['software']['name']}")

    evidence_ids = {item.evidence_id for item in context.evidence}
    evidence_complete = all(
        item.evidence_ids and set(item.evidence_ids).issubset(evidence_ids)
        for item in context.findings
    ) if context.findings else True
    status_counts = Counter(item.status.value for item in context.findings)
    return {
        "status": context.task.status.value,
        "duration_seconds": elapsed,
        "route_history": context.task.metadata.get("termination", {}).get(
            "route_history", []
        ),
        "finding_count": len(context.findings),
        "finding_status_counts": dict(sorted(status_counts.items())),
        "finding_types": sorted({item.vulnerability_type for item in context.findings}),
        "verification_count": len(context.verifications),
        "evidence_count": len(context.evidence),
        "evidence_sources": sorted({item.source for item in context.evidence}),
        "evidence_chain_complete": evidence_complete,
        "target_executed": False,
        "reports": {
            "json": str(report_json.relative_to(report_dir.parent)).replace("\\", "/"),
            "html": str(report_html.relative_to(report_dir.parent)).replace("\\", "/"),
            "pdf": str(report_pdf.relative_to(report_dir.parent)).replace("\\", "/"),
        },
    }


async def run_suite(
    manifest_paths: list[Path],
    output_dir: Path,
    *,
    upx_path: Path = DEFAULT_UPX,
    radare2_path: Path = DEFAULT_RADARE2,
    allow_transform: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run the strict protected benchmark and return rows plus intake results."""

    resolved_manifests = [path.resolve() for path in manifest_paths]
    intake = audit_manifests(resolved_manifests)
    if not intake["strict_requirement_met"]:
        raise RuntimeError("protected intake requires two ready samples per kind")

    upx = UpxAdapter(executable=str(upx_path.resolve()), timeout_seconds=20)
    radare = Radare2Adapter(
        executable=str(radare2_path.resolve()),
        timeout_seconds=20,
        # JSON is parsed before reduction to the compact experiment artifact.
        # The adapter's normal 16 KiB log cap truncates valid CFG output here.
        max_log_chars=2 * 1024 * 1024,
        max_functions=12,
        max_pseudocode_chars=4096,
    )
    rows: list[dict[str, Any]] = []
    for manifest_path in resolved_manifests:
        manifest = load_manifest(manifest_path)
        for sample in manifest["samples"]:
            target = _material_path(manifest_path, sample)
            request = BinaryAnalysisRequest(
                task_id=f"protected:{sample['sample_id']}",
                target_id=str(sample["sample_id"]),
                path=str(target),
            )
            static_result = await StaticBinaryReverseAnalyzer().analyze(request)
            obfuscation = await ObfuscationAnalyzer().inspect(static_result)
            upx_inspection = await asyncio.to_thread(
                upx.inspect, target, authorized=True
            )
            radare_inspection = await asyncio.to_thread(
                radare.inspect,
                target,
                authorized=True,
                include_pseudocode=True,
                tool_versions=True,
            )

            transform: dict[str, Any] = {
                "authorized": bool(sample["authorization"]["tool_transform"]),
                "requested": False,
                "executed": False,
                "status": "not_requested",
                "target_executed": False,
            }
            if (
                allow_transform
                and sample["authorization"]["tool_transform"] is True
                and str(sample["protection"]["product"]).casefold() == "upx"
            ):
                unpack = await asyncio.to_thread(
                    upx.unpack,
                    target,
                    output_dir=output_dir / "transformed" / str(sample["sample_id"]),
                    authorized=True,
                )
                transform = _upx_summary(unpack)
                transform.update(
                    {
                        "authorized": True,
                        "requested": True,
                        "executed": unpack.executed,
                        "target_executed": False,
                    }
                )
                output_path = (unpack.facts or {}).get("output_path")
                if unpack.status == "ok" and isinstance(output_path, str):
                    derived = await StaticBinaryReverseAnalyzer().analyze(
                        request.model_copy(update={"path": output_path})
                    )
                    derived_obfuscation = await ObfuscationAnalyzer().inspect(derived)
                    transform["derived_analysis"] = {
                        "sha256": derived.metadata.get("sha256"),
                        "size_bytes": derived.metadata.get("size_bytes"),
                        "file_format": derived.file_format,
                        "architecture": derived.architecture,
                        "packing_signal_score": derived.metadata.get(
                            "packing_signals", {}
                        ).get("signal_score", 0),
                        "obfuscation_score": derived_obfuscation.get("score", 0),
                    }

            pipeline = await _pipeline_result(
                sample, target, output_dir / "reports"
            )
            packing = static_result.metadata.get("packing_signals", {})
            base_signals = list(packing.get("signals", []))
            deeper_signals = [
                str(item.get("name"))
                for item in obfuscation.get("signals", [])
                if isinstance(item, Mapping) and item.get("name")
            ]
            signal_observed = bool(base_signals or deeper_signals)
            rows.append(
                {
                    "sample_id": sample["sample_id"],
                    "protection_kind": sample["protection"]["kind"],
                    "software": sample["software"],
                    "protection": sample["protection"],
                    "provenance": sample["provenance"],
                    "authorization": sample["authorization"],
                    "expected_observations": sample["expected_observations"],
                    "binary": {
                        "sha256": static_result.metadata.get("sha256"),
                        "size_bytes": static_result.metadata.get("size_bytes"),
                        "file_format": static_result.file_format,
                        "architecture": static_result.architecture,
                        "section_count": len(static_result.metadata.get("sections", [])),
                        "import_count": len(static_result.imports),
                        "declared_function_count": len(static_result.functions),
                    },
                    "static_signals": {
                        "observed": signal_observed,
                        "packing_score": packing.get("signal_score", 0),
                        "packing_signals": base_signals,
                        "obfuscation_score": obfuscation.get("score", 0),
                        "obfuscation_signals": deeper_signals,
                        "limitations": obfuscation.get("limitations", []),
                    },
                    "tools": {
                        "upx_inspection": _upx_summary(upx_inspection),
                        "radare2_inspection": _radare_summary(radare_inspection),
                        "transform": transform,
                    },
                    "pipeline": pipeline,
                    "target_executed": False,
                }
            )
    return rows, intake


def calculate_summary(rows: list[Mapping[str, Any]], intake: Mapping[str, Any]) -> dict[str, Any]:
    """Calculate non-inflated protected-sample counts without vulnerability GT."""

    status_counts: Counter[str] = Counter()
    for row in rows:
        pipeline = row.get("pipeline", {})
        if isinstance(pipeline, Mapping):
            raw = pipeline.get("finding_status_counts", {})
            if isinstance(raw, Mapping):
                status_counts.update({str(key): int(value) for key, value in raw.items()})
    return {
        "sample_count": len(rows),
        "packing_samples": sum(row.get("protection_kind") == "packing" for row in rows),
        "obfuscation_samples": sum(
            row.get("protection_kind") == "obfuscation" for row in rows
        ),
        "strict_intake_met": bool(intake.get("strict_requirement_met")),
        "static_signal_observed_count": sum(
            bool(row.get("static_signals", {}).get("observed"))
            for row in rows
            if isinstance(row.get("static_signals"), Mapping)
        ),
        "pipeline_completed_count": sum(
            row.get("pipeline", {}).get("status") == "completed"
            for row in rows
            if isinstance(row.get("pipeline"), Mapping)
        ),
        "pseudocode_available_count": sum(
            int(row.get("tools", {}).get("radare2_inspection", {}).get("pseudocode_count", 0)) > 0
            for row in rows
            if isinstance(row.get("tools"), Mapping)
        ),
        "file_transform_success_count": sum(
            row.get("tools", {}).get("transform", {}).get("status") == "ok"
            for row in rows
            if isinstance(row.get("tools"), Mapping)
        ),
        "finding_status_counts": dict(sorted(status_counts.items())),
        "evidence_chain_complete_count": sum(
            bool(row.get("pipeline", {}).get("evidence_chain_complete"))
            for row in rows
            if isinstance(row.get("pipeline"), Mapping)
        ),
        "target_execution_count": sum(bool(row.get("target_executed")) for row in rows),
        "vulnerability_ground_truth_available": False,
        "precision_recall_reported": False,
        "scope_note": (
            "This benchmark validates protected-binary intake and static analysis; "
            "the selected challenges do not provide vulnerability ground truth, so "
            "it does not claim exploit success or vulnerability detection recall."
        ),
    }


def render_summary(rows: list[Mapping[str, Any]], summary: Mapping[str, Any]) -> str:
    """Render a concise course-facing summary with attribution and limitations."""

    lines = [
        "# VulnAgent Part 6B 受保护闭源样本实验",
        "",
        "> 全程仅静态分析；没有执行任何样本。样本来自允许非商业课程使用的 crackmes.one，并保留作者署名。",
        "",
        "| 类别 | 软件 / 作者 | 保护方式 | 静态信号 | Findings | 复核状态 | 报告 |",
        "|---|---|---|---|---:|---|---|",
    ]
    for row in rows:
        pipeline = row["pipeline"]
        statuses = pipeline["finding_status_counts"]
        status_text = ", ".join(f"{key}:{value}" for key, value in statuses.items()) or "无候选"
        reports = pipeline["reports"]
        lines.append(
            "| {kind} | {name} / {author} | {product} | {signal} | {findings} | {status} | "
            "[HTML]({html}) / [PDF]({pdf}) |".format(
                kind=row["protection_kind"],
                name=row["software"]["name"],
                author=row["software"].get("author", "—"),
                product=row["protection"]["product"],
                signal="是" if row["static_signals"]["observed"] else "否",
                findings=pipeline["finding_count"],
                status=status_text,
                html=reports["html"],
                pdf=reports["pdf"],
            )
        )
    lines.extend(
        [
            "",
            "## 汇总",
            "",
            f"- 严格准入：{summary['strict_intake_met']}（packing=2，obfuscation=2）；",
            f"- 静态信号：{summary['static_signal_observed_count']}/{summary['sample_count']}；",
            f"- 主链完成：{summary['pipeline_completed_count']}/{summary['sample_count']}；",
            f"- radare2 伪代码可用：{summary['pseudocode_available_count']}/{summary['sample_count']}；",
            f"- 文件变换成功：{summary['file_transform_success_count']}（仅授权 UPX 解包）；",
            f"- 目标执行次数：{summary['target_execution_count']}；",
            "",
            "## 诚实边界",
            "",
            "四个样本证明系统能够在合法授权材料上执行加壳/混淆识别、工具规划、静态逆向、独立复核与报告闭环。"
            "它们没有发布漏洞 Ground Truth，因此不计算 Precision/Recall，也不把口令挑战求解冒充漏洞利用成功。",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", action="append", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--upx", type=Path, default=DEFAULT_UPX)
    parser.add_argument("--radare2", type=Path, default=DEFAULT_RADARE2)
    parser.add_argument("--allow-transform", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    output_dir = args.output_dir.resolve()
    rows, intake = asyncio.run(
        run_suite(
            args.manifest,
            output_dir,
            upx_path=args.upx,
            radare2_path=args.radare2,
            allow_transform=args.allow_transform,
        )
    )
    summary = calculate_summary(rows, intake)
    manifests = [path.resolve() for path in args.manifest]
    run_manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "suite_id": "vulnagent-protected-closed-source-v04",
        "manifests": [
            {"path": str(path), "sha256": _sha256(path)} for path in manifests
        ],
        "python": platform.python_version(),
        "host_platform": platform.platform(),
        "tools": {
            "upx": _tool_version(UpxAdapter(executable=str(args.upx.resolve())).version(authorized=True)),
            "radare2": _tool_version(Radare2Adapter(executable=str(args.radare2.resolve())).version(authorized=True)),
        },
        "target_execution": False,
        "file_transform_authorized": bool(args.allow_transform),
        "sample_count": len(rows),
    }
    _write_json_atomic(output_dir / "analysis_results.json", rows)
    _write_json_atomic(output_dir / "metrics.json", summary)
    _write_json_atomic(output_dir / "run_manifest.json", run_manifest)
    _write_text_atomic(output_dir / "summary.md", render_summary(rows, summary))
    LOGGER.info(
        "Completed protected benchmark: samples=%d signals=%d target_executions=%d",
        len(rows),
        summary["static_signal_observed_count"],
        summary["target_execution_count"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
