"""One-command V0.4 live demo and experiment-snapshot bundle builder."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnagent.report.html import write_report_html
from vulnagent.report.pdf import write_report_pdf

if __package__:
    from .demo_binary_v03 import _build_sample, run_demo as run_binary_demo
    from .demo_fuzz_v03 import run_demo as run_fuzz_demo
    from .demo_source_v03 import run_demo as run_source_demo
else:  # direct ``python scripts/demo_v04.py`` execution
    from demo_binary_v03 import _build_sample, run_demo as run_binary_demo
    from demo_fuzz_v03 import run_demo as run_fuzz_demo
    from demo_source_v03 import run_demo as run_source_demo


LOGGER = logging.getLogger("vulnagent.demo.v04")
ROOT = Path(__file__).resolve().parents[1]
_SNAPSHOTS = {
    "source_ablation": (
        Path("artifacts/experiments/source-ablation"),
        Path("benchmarks/manifest.json"),
        False,
    ),
    "binary_benchmark": (
        Path("artifacts/experiments/binary-benchmark"),
        Path("benchmarks/binary/manifest.json"),
        False,
    ),
    "fuzz_ablation": (
        Path("artifacts/experiments/fuzz-ablation"),
        Path("benchmarks/fuzz/manifest.json"),
        False,
    ),
    "llm_comparison": (
        Path("artifacts/experiments/llm-comparison"),
        Path("benchmarks/manifest.json"),
        True,
    ),
    "elf_benchmark": (
        Path("artifacts/experiments/elf-benchmark"),
        Path("benchmarks/elf/manifest.json"),
        False,
    ),
}
_PROTECTED_MANIFESTS = {
    "packing": Path("benchmarks/packed/manifest.json"),
    "obfuscation": Path("benchmarks/obfuscated/manifest.json"),
}
_PROTECTED_READINESS = Path("artifacts/experiments/protected-readiness/readiness.json")
_PROTECTED_BENCHMARK = Path("artifacts/experiments/protected-benchmark")
_PUBLIC_METERING_FIELDS = frozenset(
    {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cached_prompt_tokens",
        "usage_available_count",
        "token_cost",
        "mean_token_cost",
        "total_token_cost",
        "token_cost_currency",
        "token_cost_is_estimate",
    }
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _write_json_atomic(path: Path, value: Any) -> None:
    _write_text_atomic(path, json.dumps(value, indent=2, ensure_ascii=False))


def _reject_sensitive_fields(value: Any, location: str = "root") -> None:
    """Reject credential-shaped values before they enter the demo bundle."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            sensitive_name = (
                "api_key" in normalized
                or "secret" in normalized
                or (
                    "token" in normalized
                    and normalized not in _PUBLIC_METERING_FIELDS
                )
            )
            if sensitive_name:
                if child not in (None, False, "", "redacted", "<redacted>"):
                    raise ValueError(f"sensitive field rejected at {location}.{key}")
            _reject_sensitive_fields(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive_fields(child, f"{location}[{index}]")


def collect_experiment_snapshots(root: Path = ROOT) -> dict[str, dict[str, Any]]:
    """Load existing experiment outputs without starting models or targets."""
    snapshots: dict[str, dict[str, Any]] = {}
    for name, (relative_output, relative_manifest, paid) in _SNAPSHOTS.items():
        output_dir = root / relative_output
        manifest_path = root / relative_manifest
        run_path = output_dir / "run_manifest.json"
        metrics_path = output_dir / "metrics.json"
        base: dict[str, Any] = {
            "name": name,
            "paid_provider_snapshot": paid,
            "external_call_started": False,
            "output_dir": str(relative_output).replace("\\", "/"),
        }
        if not run_path.is_file() or not metrics_path.is_file():
            snapshots[name] = {**base, "status": "not_run", "metrics": []}
            continue
        run_manifest = _read_json(run_path)
        metrics = _read_json(metrics_path)
        if not isinstance(run_manifest, dict) or not isinstance(metrics, list):
            snapshots[name] = {**base, "status": "invalid", "metrics": []}
            continue
        recorded_hash = run_manifest.get("manifest_sha256")
        current_hash = _sha256(manifest_path) if manifest_path.is_file() else None
        same_scope = bool(recorded_hash and current_hash and recorded_hash == current_hash)
        if same_scope:
            status = "current"
        elif paid:
            status = "frozen_prior_scope"
        else:
            status = "stale"
        snapshot = {
            **base,
            "status": status,
            "manifest_scope_matches_current": same_scope,
            "recorded_manifest_sha256": recorded_hash,
            "current_manifest_sha256": current_hash,
            "run_manifest": run_manifest,
            "metrics": metrics,
        }
        _reject_sensitive_fields(snapshot, name)
        snapshots[name] = snapshot
    return snapshots


def collect_protected_readiness(root: Path = ROOT) -> dict[str, Any]:
    """Load the strict packed/obfuscated intake gate without reading samples."""

    path = root / _PROTECTED_READINESS
    if not path.is_file():
        return {
            "status": "not_run",
            "strict_requirement_met": False,
            "ready_distinct_software": {"packing": 0, "obfuscation": 0},
        }
    value = _read_json(path)
    if not isinstance(value, dict):
        return {
            "status": "invalid",
            "strict_requirement_met": False,
            "ready_distinct_software": {"packing": 0, "obfuscation": 0},
        }
    recorded = {
        item.get("protection_kind"): item.get("sha256")
        for item in value.get("manifests", [])
        if isinstance(item, dict)
    }
    current = {
        kind: _sha256(root / relative)
        for kind, relative in _PROTECTED_MANIFESTS.items()
        if (root / relative).is_file()
    }
    same_scope = recorded == current
    result = {
        "status": "current" if same_scope else "stale",
        "manifest_scope_matches_current": same_scope,
        "strict_requirement_met": bool(value.get("strict_requirement_met", False)),
        "required_distinct_software_per_kind": value.get(
            "required_distinct_software_per_kind", 2
        ),
        "ready_distinct_software": value.get(
            "ready_distinct_software", {"packing": 0, "obfuscation": 0}
        ),
        "target_execution": bool(value.get("target_execution", False)),
        "output_path": str(_PROTECTED_READINESS).replace("\\", "/"),
    }
    _reject_sensitive_fields(result, "protected_readiness")
    return result


def collect_protected_benchmark(root: Path = ROOT) -> dict[str, Any]:
    """Load the Part 6B static benchmark and reject stale manifest scope."""

    output_dir = root / _PROTECTED_BENCHMARK
    metrics_path = output_dir / "metrics.json"
    run_path = output_dir / "run_manifest.json"
    if not metrics_path.is_file() or not run_path.is_file():
        return {
            "status": "not_run",
            "sample_count": 0,
            "target_execution_count": 0,
        }
    metrics = _read_json(metrics_path)
    run_manifest = _read_json(run_path)
    if not isinstance(metrics, dict) or not isinstance(run_manifest, dict):
        return {
            "status": "invalid",
            "sample_count": 0,
            "target_execution_count": 0,
        }
    recorded_hashes = {
        str(item.get("sha256"))
        for item in run_manifest.get("manifests", [])
        if isinstance(item, dict) and item.get("sha256")
    }
    current_hashes = {
        _sha256(root / relative)
        for relative in _PROTECTED_MANIFESTS.values()
        if (root / relative).is_file()
    }
    same_scope = bool(recorded_hashes) and recorded_hashes == current_hashes
    result = {
        "status": "current" if same_scope else "stale",
        "manifest_scope_matches_current": same_scope,
        "sample_count": metrics.get("sample_count", 0),
        "static_signal_observed_count": metrics.get(
            "static_signal_observed_count", 0
        ),
        "pipeline_completed_count": metrics.get("pipeline_completed_count", 0),
        "pseudocode_available_count": metrics.get(
            "pseudocode_available_count", 0
        ),
        "file_transform_success_count": metrics.get(
            "file_transform_success_count", 0
        ),
        "evidence_chain_complete_count": metrics.get(
            "evidence_chain_complete_count", 0
        ),
        "target_execution_count": metrics.get("target_execution_count", 0),
        "vulnerability_ground_truth_available": bool(
            metrics.get("vulnerability_ground_truth_available", False)
        ),
        "precision_recall_reported": bool(
            metrics.get("precision_recall_reported", False)
        ),
        "output_dir": str(_PROTECTED_BENCHMARK).replace("\\", "/"),
    }
    _reject_sensitive_fields(result, "protected_benchmark")
    return result


def _metric_rows(snapshots: dict[str, dict[str, Any]]) -> list[str]:
    rows = [
        "| 实验快照 | 状态 | 方法 | 样本 | Precision | Recall | F1 | Evidence Coverage |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for snapshot_name, snapshot in snapshots.items():
        metrics = snapshot.get("metrics", [])
        if not metrics:
            rows.append(f"| {snapshot_name} | {snapshot['status']} | — | — | — | — | — | — |")
            continue
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            rows.append(
                "| {snapshot} | {status} | {method} | {samples} | {precision} | "
                "{recall} | {f1} | {coverage} |".format(
                    snapshot=snapshot_name,
                    status=snapshot["status"],
                    method=metric.get("method", "—"),
                    samples=metric.get("samples", "—"),
                    precision=_display(metric.get("precision")),
                    recall=_display(metric.get("recall")),
                    f1=_display(metric.get("f1")),
                    coverage=_display(metric.get("evidence_chain_coverage")),
                )
            )
    return rows


def _display(value: Any) -> str:
    return f"{value:.3f}" if isinstance(value, float) else str(value if value is not None else "—")


def render_summary(bundle: dict[str, Any]) -> str:
    """Render a compact human-facing index with explicit scope boundaries."""
    live = bundle["live_demo"]
    lines = [
        "# VulnAgent V0.4 一键演示摘要",
        "",
        f"> 生成时间：{bundle['generated_at']}",
        "> 本次命令不会调用外部 LLM；LLM 数据只读取既有、带 manifest 哈希的实验快照。",
        "",
        "## 现场主链",
        "",
        "| 模块 | 状态 | Findings | Confirmed | 目标执行 |",
        "|---|---|---:|---:|---|",
    ]
    for name in ("source", "binary", "fuzz"):
        item = live[name]
        lines.append(
            f"| {name} | {item['status']} | {item['finding_count']} | "
            f"{item['confirmed_count']} | {item['target_executed']} |"
        )
    artifacts = bundle.get("artifacts", {})
    report_links: list[str] = []
    for name in ("source", "binary", "fuzz"):
        links = []
        html_path = artifacts.get(f"{name}_html")
        pdf_path = artifacts.get(f"{name}_pdf")
        if html_path:
            links.append(f"[HTML]({html_path})")
        if pdf_path:
            links.append(f"[PDF]({pdf_path})")
        if links:
            report_links.append(f"- {name.title()}：{' / '.join(links)}")
    if report_links:
        lines.extend(["", "## 可直接打开的离线报告", "", *report_links])
    benchmark_links = []
    for label, key in (
        ("LLM Usage/Cost 汇总", "llm_comparison_summary"),
        ("Part 6B 受保护样本汇总", "protected_benchmark_summary"),
        ("真实 ELF Benchmark 汇总", "elf_benchmark_summary"),
    ):
        path = artifacts.get(key)
        if path:
            benchmark_links.append(f"- [{label}]({path})")
    if benchmark_links:
        lines.extend(["", "## 可直接打开的专项实验", "", *benchmark_links])
    lines.extend(["", "## 实验快照（按 manifest 校验）", "", *_metric_rows(bundle["experiments"])])
    protected = bundle.get(
        "protected_readiness",
        {
            "status": "not_run",
            "strict_requirement_met": False,
            "ready_distinct_software": {"packing": 0, "obfuscation": 0},
        },
    )
    ready = protected.get("ready_distinct_software", {})
    lines.extend(
        [
            "",
            "## 加壳/混淆闭源样本就绪门禁",
            "",
            "| 状态 | 加壳软件就绪数 | 混淆软件就绪数 | 严格课程要求已满足 |",
            "|---|---:|---:|---|",
            f"| {protected.get('status', 'not_run')} | {ready.get('packing', 0)} | "
            f"{ready.get('obfuscation', 0)} | {protected.get('strict_requirement_met', False)} |",
        ]
    )
    protected_benchmark = bundle.get(
        "protected_benchmark",
        {"status": "not_run", "sample_count": 0, "target_execution_count": 0},
    )
    lines.extend(
        [
            "",
            "## Part 6B 受保护样本静态实测",
            "",
            "| 状态 | 样本 | 静态信号 | 主链完成 | 可生成伪代码 | Evidence 完整 | 目标执行 |",
            "|---|---:|---:|---:|---:|---:|---:|",
            f"| {protected_benchmark.get('status', 'not_run')} | "
            f"{protected_benchmark.get('sample_count', 0)} | "
            f"{protected_benchmark.get('static_signal_observed_count', 0)} | "
            f"{protected_benchmark.get('pipeline_completed_count', 0)} | "
            f"{protected_benchmark.get('pseudocode_available_count', 0)} | "
            f"{protected_benchmark.get('evidence_chain_complete_count', 0)} | "
            f"{protected_benchmark.get('target_execution_count', 0)} |",
        ]
    )
    elf_status = bundle.get("experiments", {}).get("elf_benchmark", {}).get(
        "status", "not_run"
    )
    llm_snapshot = bundle.get("experiments", {}).get("llm_comparison", {})
    llm_status = llm_snapshot.get("status", "not_run")
    llm_metrics = llm_snapshot.get("metrics", [])
    llm_samples = next(
        (
            item.get("samples")
            for item in llm_metrics
            if isinstance(item, dict) and str(item.get("method", "")).startswith("llm_only:")
        ),
        "unknown",
    )
    lines.extend(
        [
            "",
            "## 必须说明的边界",
            "",
            "- Source/Binary Benchmark 只读目标；Fuzz 只执行项目自研且显式授权的本地靶标。",
            f"- LLM 对比当前状态为 `{llm_status}`、每个模型 {llm_samples} 个样本；只有 manifest 哈希一致时才标为 `current`。",
            f"- 真实 ELF 由 Zig 交叉编译并完成只读实验，当前快照状态为 `{elf_status}`；ELF 文件没有被执行。",
            "- 四个受保护样本来自明确的教育逆向挑战，实验只做静态读取/工具变换，不执行目标，也不把它们冒充含漏洞 Ground Truth 的样本。",
            "- 小样本 F1=1.0 不代表真实世界 100% 检出率。",
            "",
        ]
    )
    return "\n".join(lines)


def _live_summary(result: dict[str, object], *, target_executed: bool) -> dict[str, Any]:
    findings = result.get("findings", [])
    verifications = result.get("verifications", [])
    verification_rows = verifications if isinstance(verifications, list) else []
    confirmed = sum(
        isinstance(item, dict) and item.get("status") == "confirmed"
        for item in verification_rows
    )
    return {
        "status": result.get("status"),
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "confirmed_count": confirmed,
        "target_executed": target_executed,
        "route_history": result.get("route_history", []),
    }


async def run_bundle(
    output_dir: Path,
    *,
    binary_target: Path | None = None,
    include_fuzz: bool = True,
    include_pdf: bool = True,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Run local demos and write a scope-aware bundle; never call an LLM provider."""
    output_dir = output_dir.resolve()
    source_result = await run_source_demo(output_dir / "source.json")
    target = binary_target.resolve() if binary_target else _build_sample(
        output_dir / "binary-demo.exe"
    )
    binary_result = await run_binary_demo(target, output_dir / "binary.json")
    if include_fuzz:
        fuzz_result = await run_fuzz_demo(
            root / "samples" / "fuzz_demo" / "target.py",
            root / "samples" / "fuzz_demo" / "seeds",
            output_dir / "fuzz.json",
        )
    else:
        fuzz_result = {
            "status": "skipped",
            "findings": [],
            "verifications": [],
            "route_history": [],
        }
    live_reports = {
        "source": source_result,
        "binary": binary_result,
        "fuzz": fuzz_result,
    }
    for name, result in live_reports.items():
        report = result.get("report")
        if isinstance(report, dict):
            write_report_html(
                report,
                output_dir / f"{name}.html",
                title=f"VulnAgent V0.4 · {name.title()} 报告",
            )
            if include_pdf:
                write_report_pdf(
                    report,
                    output_dir / f"{name}.pdf",
                    title=f"VulnAgent V0.4 · {name.title()} 报告",
                )
    bundle = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "external_llm_calls_started": False,
        "live_demo": {
            "source": _live_summary(source_result, target_executed=False),
            "binary": _live_summary(binary_result, target_executed=False),
            "fuzz": _live_summary(fuzz_result, target_executed=include_fuzz),
        },
        "experiments": collect_experiment_snapshots(root),
        "protected_readiness": collect_protected_readiness(root),
        "protected_benchmark": collect_protected_benchmark(root),
        "artifacts": {
            "source": "source.json",
            "binary": "binary.json",
            "fuzz": "fuzz.json" if include_fuzz else None,
            "source_html": "source.html",
            "binary_html": "binary.html",
            "fuzz_html": "fuzz.html" if include_fuzz else None,
            "source_pdf": "source.pdf" if include_pdf else None,
            "binary_pdf": "binary.pdf" if include_pdf else None,
            "fuzz_pdf": "fuzz.pdf" if include_fuzz and include_pdf else None,
            "summary": "summary.md",
            "protected_readiness": "../../experiments/protected-readiness/readiness.json",
            "llm_comparison_summary": "../../experiments/llm-comparison/summary.md",
            "protected_benchmark_summary": "../../experiments/protected-benchmark/summary.md",
            "elf_benchmark_summary": "../../experiments/elf-benchmark/summary.md",
        },
    }
    _reject_sensitive_fields(bundle)
    _write_json_atomic(output_dir / "index.json", bundle)
    _write_text_atomic(output_dir / "summary.md", render_summary(bundle))
    return bundle


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the V0.4 one-command local demo.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "artifacts" / "demos" / "v04",
    )
    parser.add_argument("--binary-target", type=Path)
    parser.add_argument(
        "--skip-fuzz",
        action="store_true",
        help="Skip the explicitly authorized dynamic demo and run only read-only paths.",
    )
    parser.add_argument(
        "--skip-pdf",
        action="store_true",
        help="Skip optional printable PDF artifacts; HTML and JSON are still generated.",
    )
    args = parser.parse_args()
    bundle = asyncio.run(
        run_bundle(
            args.output_dir,
            binary_target=args.binary_target,
            include_fuzz=not args.skip_fuzz,
            include_pdf=not args.skip_pdf,
        )
    )
    LOGGER.info(
        "V0.4 demo completed: source=%s binary=%s fuzz=%s summary=%s",
        bundle["live_demo"]["source"]["status"],
        bundle["live_demo"]["binary"]["status"],
        bundle["live_demo"]["fuzz"]["status"],
        args.output_dir.resolve() / "summary.md",
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
