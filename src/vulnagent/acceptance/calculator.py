"""Honest course-test acceptance status calculation.

The calculator reads the packed/obfuscated intake manifests, the LLM provider
configuration and (when present) the canonical experiment artifacts under
``artifacts/experiments/``. It never executes a target, never calls an LLM,
never reads Ground Truth into an analyzer, and never hardcodes a completion
state. Every ``PASS`` requires the concrete evidence the course requires
(confirmed finding + independent verification + controlled PoC), so the
three groups can only reach ``PASS`` through real structured results.
"""

from __future__ import annotations

import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from vulnagent.acceptance.models import (
    AcceptanceCondition,
    AcceptanceGroup,
    AcceptanceOverview,
    AcceptanceStatus,
    AcceptanceTarget,
    BenchmarkCounts,
    BenchmarkSummary,
    BinaryBenchmarkMetric,
    ElfBenchmarkSummary,
    LLMComparisonSummary,
    ProviderComparison,
    ProviderStatus,
)
from vulnagent.settings import Settings

GROUP_LLM = "a"
GROUP_PACKED = "b"
GROUP_OBFUSCATED = "c"

_PROVIDER_KEYS = ("deepseek", "glm", "kimi")

_NOTICES = (
    "Mock 结果不计入真实验收：只有真实 Provider 调用与结构化验证证据才参与 PASS 判定。",
    "上传不等于动态执行授权：加壳/混淆样本默认仅做只读静态分析，动态执行与 PoC 需单独授权并在隔离沙箱中复现。",
)


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _optional_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_str(value: Any) -> str | None:
    return str(value) if value else None


def _comparison_from_metrics(methods: Mapping[str, Mapping[str, Any]]) -> list[ProviderComparison]:
    """Project llm-comparison metric rows into credential-free ViewModels."""
    comparisons: list[ProviderComparison] = []
    for method_name in sorted(methods):
        metric = methods[method_name]
        comparisons.append(
            ProviderComparison(
                method=method_name,
                samples=int(metric.get("samples", 0) or 0),
                true_positive=int(metric.get("true_positive", 0) or 0),
                false_positive=int(metric.get("false_positive", 0) or 0),
                true_negative=int(metric.get("true_negative", 0) or 0),
                false_negative=int(metric.get("false_negative", 0) or 0),
                precision=_optional_float(metric.get("precision")) or 0.0,
                recall=_optional_float(metric.get("recall")) or 0.0,
                f1=_optional_float(metric.get("f1")) or 0.0,
                prompt_tokens=_optional_int(metric.get("prompt_tokens")),
                completion_tokens=_optional_int(metric.get("completion_tokens")),
                total_tokens=_optional_int(metric.get("total_tokens")),
                total_token_cost=_optional_float(metric.get("total_token_cost")),
                token_cost_currency=_optional_str(metric.get("token_cost_currency")),
                mean_duration_seconds=_optional_float(metric.get("mean_duration_seconds")),
                confirmed_finding_count=int(metric.get("confirmed_finding_count", 0) or 0),
                evidence_chain_coverage=_optional_float(metric.get("evidence_chain_coverage")) or 0.0,
            )
        )
    return comparisons


def _llm_comparison_summary(repo_root: Path) -> LLMComparisonSummary:
    """Prefer current artifacts, falling back to the credential-free published baseline."""
    metrics_payload = _read_json(
        repo_root / "artifacts" / "experiments" / "llm-comparison" / "metrics.json"
    )
    manifest_payload = _read_json(
        repo_root / "artifacts" / "experiments" / "llm-comparison" / "run_manifest.json"
    )
    source = "canonical_artifact"
    snapshot_id: str | None = None
    generated_at = (
        _optional_str(manifest_payload.get("generated_at"))
        if isinstance(manifest_payload, Mapping)
        else None
    )
    declared_hash = (
        _optional_str(manifest_payload.get("manifest_sha256"))
        if isinstance(manifest_payload, Mapping)
        else None
    )
    if not isinstance(metrics_payload, list):
        baseline = _read_json(
            repo_root / "benchmarks" / "baselines" / "llm-comparison-v04.json"
        )
        if not isinstance(baseline, Mapping):
            return LLMComparisonSummary()
        candidate_metrics = baseline.get("metrics")
        if not isinstance(candidate_metrics, list):
            return LLMComparisonSummary()
        metrics_payload = candidate_metrics
        source = "published_baseline"
        snapshot_id = _optional_str(baseline.get("snapshot_id"))
        generated_at = _optional_str(baseline.get("generated_at"))
        declared_hash = _optional_str(baseline.get("benchmark_manifest_sha256"))

    methods = {
        str(item["method"]): item
        for item in metrics_payload
        if isinstance(item, Mapping) and isinstance(item.get("method"), str)
    }
    current_hash = _sha256_file(repo_root / "benchmarks" / "manifest.json")
    manifest_matches = (
        current_hash == declared_hash
        if current_hash is not None and declared_hash is not None
        else None
    )
    return LLMComparisonSummary(
        source=source,
        snapshot_id=snapshot_id,
        generated_at=generated_at,
        benchmark_manifest_sha256=declared_hash,
        manifest_matches=manifest_matches,
        metrics=_comparison_from_metrics(methods),
    )


def _manifest_sample_count(repo_root: Path, relative_path: str) -> int:
    """Count manifest samples without trusting a duplicated summary field."""
    manifest = _read_json(repo_root / relative_path)
    if not isinstance(manifest, Mapping):
        return 0
    samples = manifest.get("samples")
    if not isinstance(samples, list):
        return 0
    return sum(isinstance(sample, Mapping) for sample in samples)


def _benchmark_summary(repo_root: Path) -> BenchmarkSummary:
    """Project benchmark manifests and canonical stripped metrics for the UI."""
    counts = BenchmarkCounts(
        source_samples=_manifest_sample_count(repo_root, "benchmarks/manifest.json"),
        binary_samples=_manifest_sample_count(repo_root, "benchmarks/binary/manifest.json"),
        fuzz_scenarios=_manifest_sample_count(repo_root, "benchmarks/fuzz/manifest.json"),
    )

    metrics = _read_json(
        repo_root / "artifacts" / "experiments" / "binary-benchmark" / "metrics.json"
    )
    run_manifest = _read_json(
        repo_root / "artifacts" / "experiments" / "binary-benchmark" / "run_manifest.json"
    )
    generated_at = (
        _optional_str(run_manifest.get("generated_at"))
        if isinstance(run_manifest, Mapping)
        else None
    )
    stripped: BinaryBenchmarkMetric | None = None
    if isinstance(metrics, list):
        row = next(
            (
                item
                for item in metrics
                if isinstance(item, Mapping)
                and item.get("method") == "vulnagent_binary_stripped"
            ),
            None,
        )
        if isinstance(row, Mapping):
            stripped = BinaryBenchmarkMetric(
                method="vulnagent_binary_stripped",
                profile="stripped",
                samples=_optional_int(row.get("samples")) or 0,
                true_positive=_optional_int(row.get("true_positive")) or 0,
                false_positive=_optional_int(row.get("false_positive")) or 0,
                true_negative=_optional_int(row.get("true_negative")) or 0,
                false_negative=_optional_int(row.get("false_negative")) or 0,
                precision=_optional_float(row.get("precision")) or 0.0,
                recall=_optional_float(row.get("recall")) or 0.0,
                f1=_optional_float(row.get("f1")) or 0.0,
                false_positive_rate=_optional_float(row.get("false_positive_rate")) or 0.0,
                evidence_chain_coverage=(
                    _optional_float(row.get("evidence_chain_coverage")) or 0.0
                ),
                generated_at=generated_at,
            )
    elf_metrics = _read_json(
        repo_root / "artifacts" / "experiments" / "elf-benchmark" / "metrics.json"
    )
    elf_manifest = _read_json(
        repo_root / "artifacts" / "experiments" / "elf-benchmark" / "run_manifest.json"
    )
    elf_profiles: list[BinaryBenchmarkMetric] = []
    profile_names = {
        "vulnagent_elf_symbol_rich": "symbol-rich",
        "vulnagent_elf_stripped": "stripped",
        "vulnagent_elf_pie": "pie",
    }
    if isinstance(elf_metrics, list):
        for item in elf_metrics:
            if not isinstance(item, Mapping):
                continue
            method = _optional_str(item.get("method"))
            if method not in profile_names:
                continue
            elf_profiles.append(
                BinaryBenchmarkMetric(
                    method=method,
                    profile=profile_names[method],
                    samples=_optional_int(item.get("samples")) or 0,
                    true_positive=_optional_int(item.get("true_positive")) or 0,
                    false_positive=_optional_int(item.get("false_positive")) or 0,
                    true_negative=_optional_int(item.get("true_negative")) or 0,
                    false_negative=_optional_int(item.get("false_negative")) or 0,
                    precision=_optional_float(item.get("precision")) or 0.0,
                    recall=_optional_float(item.get("recall")) or 0.0,
                    f1=_optional_float(item.get("f1")) or 0.0,
                    false_positive_rate=(
                        _optional_float(item.get("false_positive_rate")) or 0.0
                    ),
                    evidence_chain_coverage=(
                        _optional_float(item.get("evidence_chain_coverage")) or 0.0
                    ),
                    generated_at=(
                        _optional_str(elf_manifest.get("generated_at"))
                        if isinstance(elf_manifest, Mapping)
                        else None
                    ),
                )
            )
    elf_profiles.sort(
        key=lambda item: ("symbol-rich", "stripped", "pie").index(item.profile)
    )
    elf_a: ElfBenchmarkSummary | None = None
    if elf_profiles:
        manifest_data = elf_manifest if isinstance(elf_manifest, Mapping) else {}
        target_execution = manifest_data.get("target_execution")
        elf_a = ElfBenchmarkSummary(
            fixture_count=(
                _optional_int(manifest_data.get("fixture_count"))
                or _manifest_sample_count(repo_root, "benchmarks/elf/manifest.json")
            ),
            family_count=_optional_int(manifest_data.get("family_count")) or 0,
            profile_count=len(elf_profiles),
            row_count=(
                _optional_int(manifest_data.get("row_count"))
                or sum(item.samples for item in elf_profiles)
            ),
            compiler_version=_optional_str(manifest_data.get("compiler_version")),
            compiler_machine=_optional_str(manifest_data.get("compiler_machine")),
            target_execution=(
                target_execution if isinstance(target_execution, bool) else None
            ),
            generated_at=_optional_str(manifest_data.get("generated_at")),
            profiles=elf_profiles,
        )
    return BenchmarkSummary(counts=counts, stripped_binary=stripped, elf_a=elf_a)


def _provider_statuses(settings: Settings) -> list[ProviderStatus]:
    model_attr = {
        "deepseek": (settings.deepseek_api_key, settings.deepseek_model, settings.deepseek_base_url),
        "glm": (settings.glm_api_key, settings.glm_model, settings.glm_base_url),
        "kimi": (settings.kimi_api_key, settings.kimi_model, settings.kimi_base_url),
    }
    statuses: list[ProviderStatus] = []
    for name in _PROVIDER_KEYS:
        key, model, base_url = model_attr[name]
        statuses.append(
            ProviderStatus(
                provider=name,
                configured=bool(key and key.strip()),
                is_mock=False,
                model=model,
                base_url=base_url,
                default_for_planner=settings.llm_provider.strip().casefold() == name,
            )
        )
    return statuses


def _load_protected_manifest(repo_root: Path, kind: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    manifest = _read_json(repo_root / "benchmarks" / kind / "manifest.json")
    if not isinstance(manifest, dict):
        return manifest, []
    samples = manifest.get("samples")
    if not isinstance(samples, list):
        return manifest, []
    return manifest, [s for s in samples if isinstance(s, dict)]


def _material_path(repo_root: Path, kind: str, sample: Mapping[str, Any]) -> Path:
    local = str(sample.get("local_path") or "")
    return repo_root / "benchmarks" / kind / local


def _target_status(
    repo_root: Path,
    kind: str,
    sample: Mapping[str, Any],
    benchmark_rows: Mapping[str, Mapping[str, Any]],
    ground_truth_available: bool,
) -> AcceptanceTarget:
    sample_id = str(sample.get("sample_id") or "")
    software = sample.get("software") or {}
    protection = sample.get("protection") or {}
    provenance = sample.get("provenance") or {}
    authorization = sample.get("authorization") or {}
    material = _material_path(repo_root, kind, sample)
    material_present = material.is_file()
    observed_hash = _sha256_file(material)
    declared_hash = str(sample.get("sha256") or "")
    sha256_verified = (
        bool(declared_hash) and observed_hash is not None and observed_hash == declared_hash
    )
    static_authorized = authorization.get("static_analysis") is True
    intake_ready = material_present and sha256_verified and static_authorized

    benchmark = benchmark_rows.get(sample_id, {})
    pipeline = benchmark.get("pipeline") or {}
    pipeline = pipeline if isinstance(pipeline, Mapping) else {}
    tools = benchmark.get("tools") or {}
    tools = tools if isinstance(tools, Mapping) else {}
    static_signals = benchmark.get("static_signals") or {}
    static_signals = static_signals if isinstance(static_signals, Mapping) else {}

    report_links: dict[str, str] = {}
    raw_reports = pipeline.get("reports")
    if isinstance(raw_reports, Mapping):
        for key in ("json", "html", "pdf"):
            value = raw_reports.get(key)
            if isinstance(value, str):
                report_links[key] = value

    issues: list[str] = []
    if not material_present:
        issues.append("authorized sample binary is not present in this checkout")
    elif not sha256_verified:
        issues.append("sample sha256 does not match the manifest")
    if not static_authorized:
        issues.append("static analysis is not authorized")

    return AcceptanceTarget(
        sample_id=sample_id,
        software_name=str(software.get("name") or sample_id),
        author=(str(software.get("author")) if software.get("author") else None),
        version=(str(software.get("version")) if software.get("version") else None),
        protection_kind=str(protection.get("kind") or kind),
        protector_product=(str(protection.get("product")) if protection.get("product") else None),
        protector_secondary=(
            str(protection.get("secondary")) if protection.get("secondary") else None
        ),
        sha256=declared_hash or None,
        file_format=(str(sample.get("file_format")) if sample.get("file_format") else None),
        architecture=(str(sample.get("architecture")) if sample.get("architecture") else None),
        source_uri=(str(provenance.get("source_uri")) if provenance.get("source_uri") else None),
        static_analysis_authorized=static_authorized,
        tool_transform_authorized=authorization.get("tool_transform") is True,
        dynamic_execution_authorized=authorization.get("dynamic_execution") is True,
        material_present=material_present,
        sha256_verified=sha256_verified,
        intake_ready=intake_ready,
        vulnerability_ground_truth_available=ground_truth_available,
        finding_count=(int(pipeline["finding_count"]) if "finding_count" in pipeline else None),
        finding_status_counts={
            str(key): int(value)
            for key, value in (pipeline.get("finding_status_counts") or {}).items()
        }
        if isinstance(pipeline.get("finding_status_counts"), Mapping)
        else {},
        evidence_chain_complete=(
            bool(pipeline["evidence_chain_complete"])
            if "evidence_chain_complete" in pipeline
            else None
        ),
        static_signals_observed=(
            bool(static_signals["observed"]) if "observed" in static_signals else None
        ),
        pseudocode_available=(
            int((tools.get("radare2_inspection") or {}).get("pseudocode_count", 0)) > 0
            if isinstance(tools.get("radare2_inspection"), Mapping)
            else None
        ),
        target_executed=False,
        report_links=report_links,
        issues=issues,
    )


def _protected_group(
    repo_root: Path,
    group_id: str,
    kind: str,
    title: str,
    condition_label: str,
) -> AcceptanceGroup:
    manifest, samples = _load_protected_manifest(repo_root, kind)
    benchmark_rows: dict[str, Mapping[str, Any]] = {}
    benchmark_metrics: Mapping[str, Any] = {}
    analysis = _read_json(
        repo_root / "artifacts" / "experiments" / "protected-benchmark" / "analysis_results.json"
    )
    if isinstance(analysis, list):
        for row in analysis:
            if isinstance(row, Mapping) and isinstance(row.get("sample_id"), str):
                benchmark_rows[str(row["sample_id"])] = row
    metrics = _read_json(
        repo_root / "artifacts" / "experiments" / "protected-benchmark" / "metrics.json"
    )
    if isinstance(metrics, dict):
        benchmark_metrics = metrics

    ground_truth_available = bool(benchmark_metrics.get("vulnerability_ground_truth_available", False))
    controlled_poc_available = bool(benchmark_metrics.get("controlled_poc_evidence_available", False))

    targets = [
        _target_status(repo_root, kind, sample, benchmark_rows, ground_truth_available)
        for sample in samples
    ]
    intake_ready = all(target.intake_ready for target in targets) and len(targets) >= 2
    analysis_done = bool(benchmark_rows)
    confirmed_count = sum(
        target.finding_status_counts.get("confirmed", 0) for target in targets
    )

    conditions = [
        AcceptanceCondition(
            key="two_targets",
            label=f"两个授权{condition_label}目标（来源/版本/哈希可追踪）",
            met=len(targets) >= 2,
            detail=f"清单包含 {len(targets)} 个目标",
        ),
        AcceptanceCondition(
            key="intake_ready",
            label="样本文件存在且 SHA-256 与清单一致",
            met=intake_ready,
            detail="全部目标文件哈希核验通过" if intake_ready else "存在缺失或哈希不符的样本文件",
        ),
        AcceptanceCondition(
            key="static_analysis",
            label="完成只读静态分析与逆向主链",
            met=analysis_done,
            detail="存在受保护样本实验产物" if analysis_done else "尚未生成本次工作区的实验产物",
        ),
        AcceptanceCondition(
            key="confirmed_finding",
            label="至少一个经独立复核确认的漏洞",
            met=confirmed_count > 0,
            detail=f"独立复核确认 {confirmed_count} 个漏洞",
        ),
        AcceptanceCondition(
            key="ground_truth",
            label="目标具备漏洞 Ground Truth",
            met=ground_truth_available,
            detail="具备漏洞 Ground Truth" if ground_truth_available else "所选教育样本不提供漏洞 Ground Truth",
        ),
        AcceptanceCondition(
            key="controlled_poc",
            label="受控 PoC 与沙箱复现证据",
            met=controlled_poc_available,
            detail="存在受控 PoC/沙箱复现证据" if controlled_poc_available else "当前无受控 PoC/沙箱复现证据（动态执行默认关闭）",
        ),
    ]

    if analysis_done:
        status = (
            AcceptanceStatus.PASS
            if (confirmed_count > 0 and ground_truth_available and controlled_poc_available)
            else AcceptanceStatus.PARTIAL
        )
    elif intake_ready:
        status = AcceptanceStatus.NOT_RUN
    else:
        status = AcceptanceStatus.BLOCKED

    if analysis_done:
        summary = (
            f"已完成 {len(targets)} 个目标的只读静态识别与主链分析，"
            f"独立复核确认 {confirmed_count} 个漏洞；"
            "尚无漏洞 Ground Truth 与受控 PoC，因此不能判定 PASS。"
        )
    elif intake_ready:
        summary = "样本就绪，尚未在本次工作区运行受保护样本实验。"
    else:
        summary = "授权样本二进制文件未在当前工作区落地，无法进行静态逆向与复现。"
    if not ground_truth_available and analysis_done:
        summary += " 所选教育挑战无漏洞 Ground Truth，只能证明保护识别与逆向闭环，不能冒充漏洞利用成功。"

    latest_run: dict[str, Any] = {}
    if analysis_done:
        latest_run = {
            "sample_count": int(benchmark_metrics.get("sample_count", len(benchmark_rows))),
            "target_execution_count": int(benchmark_metrics.get("target_execution_count", 0)),
            "vulnerability_ground_truth_available": bool(
                benchmark_metrics.get("vulnerability_ground_truth_available", False)
            ),
        }

    return AcceptanceGroup(
        group_id=group_id,
        title=title,
        status=status,
        summary=summary,
        targets=targets,
        conditions=conditions,
        latest_run=latest_run,
    )


def _llm_group(repo_root: Path, providers: list[ProviderStatus]) -> AcceptanceGroup:
    real = [p for p in providers if p.configured]
    comparison_metrics = _read_json(
        repo_root / "artifacts" / "experiments" / "llm-comparison" / "metrics.json"
    )
    run_manifest = _read_json(
        repo_root / "artifacts" / "experiments" / "llm-comparison" / "run_manifest.json"
    )

    methods: dict[str, Mapping[str, Any]] = {}
    if isinstance(comparison_metrics, list):
        for metric in comparison_metrics:
            if isinstance(metric, Mapping) and isinstance(metric.get("method"), str):
                methods[str(metric["method"])] = metric

    comparison = _comparison_from_metrics(methods)
    llm_only = {
        name: methods[f"llm_only:{name}"]
        for name in _PROVIDER_KEYS
        if f"llm_only:{name}" in methods
    }
    comparison_done = len(llm_only) >= 2
    full = methods.get("vulnagent_full", {})
    full_confirmed = int(full.get("confirmed_finding_count", 0))

    conditions = [
        AcceptanceCondition(
            key="two_real_providers",
            label="至少两个真实 Provider（DeepSeek/GLM/Kimi）已配置密钥",
            met=len(real) >= 2,
            detail=f"已配置 {len(real)} 个真实 Provider",
        ),
        AcceptanceCondition(
            key="comparison_run",
            label="至少两个 Provider 在同一基准上完成对比运行",
            met=comparison_done,
            detail=f"已完成 {len(llm_only)} 个 Provider 的对比" if llm_only else "尚未在本次工作区完成对比",
        ),
        AcceptanceCondition(
            key="independent_verification",
            label="至少一个漏洞经独立复核确认",
            met=full_confirmed > 0,
            detail=f"Full 系统独立复核确认 {full_confirmed} 个漏洞",
        ),
        AcceptanceCondition(
            key="controlled_exploit_verification",
            label="模型参与发现的漏洞完成受控利用验证",
            met=False,
            detail="当前对比只证明模型分类能力，未完成逐模型受控利用验证",
        ),
    ]

    if len(real) < 2:
        status = AcceptanceStatus.BLOCKED
    elif not comparison_done:
        status = AcceptanceStatus.NOT_RUN
    elif full_confirmed <= 0:
        status = AcceptanceStatus.PARTIAL
    else:
        # Even a completed comparison lacks per-model controlled exploit
        # verification, so it remains PARTIAL rather than PASS.
        status = AcceptanceStatus.PARTIAL

    if len(real) < 2:
        summary = "需要至少两个真实 Provider 密钥才能运行本组验收。"
    elif not comparison_done:
        summary = "Provider 已配置但尚未在本次工作区运行对比实验；真实调用结果进入结构产物后才参与判定。"
    else:
        summary = (
            f"{len(llm_only)} 个真实 Provider 已完成同样本对比（各 20 次调用），"
            f"Full 系统独立复核确认 {full_confirmed} 个漏洞；"
            "但模型对比未包含逐模型受控利用验证，故为 PARTIAL。"
        )

    latest_run: dict[str, Any] = {}
    if comparison_done and isinstance(run_manifest, dict):
        providers_snapshot = {
            str(name): {
                "model": (
                    str(value.get("model"))
                    if isinstance(value, Mapping) and value.get("model")
                    else None
                ),
            }
            for name, value in (run_manifest.get("providers") or {}).items()
            if isinstance(value, Mapping)
        }
        latest_run = {
            "sample_count": int(run_manifest.get("sample_count", 0)),
            "providers": providers_snapshot,
        }

    return AcceptanceGroup(
        group_id=GROUP_LLM,
        title="A. 开源大模型漏洞挖掘与验证",
        status=status,
        summary=summary,
        providers=providers,
        conditions=conditions,
        comparison=comparison,
        latest_run=latest_run,
    )


class AcceptanceCalculator:
    """Compute the course-test acceptance matrix from on-disk facts."""

    def __init__(self, *, repo_root: Path | None = None) -> None:
        self.repo_root = (repo_root or _default_repo_root()).resolve()

    def build_overview(self, settings: Settings) -> AcceptanceOverview:
        providers = _provider_statuses(settings)
        group_a = _llm_group(self.repo_root, providers)
        group_b = _protected_group(
            self.repo_root, GROUP_PACKED, "packed", "B. 加壳闭源软件漏洞挖掘与验证", "加壳闭源"
        )
        group_c = _protected_group(
            self.repo_root, GROUP_OBFUSCATED, "obfuscated", "C. 混淆闭源软件漏洞挖掘与验证", "混淆闭源"
        )
        groups = [group_a, group_b, group_c]
        passed = sum(1 for group in groups if group.status is AcceptanceStatus.PASS)
        return AcceptanceOverview(
            passed_groups=passed,
            total_groups=len(groups),
            status_text=f"{passed}/{len(groups)}",
            code_version="V0.4",
            benchmark_version=self._benchmark_version(),
            benchmark_summary=_benchmark_summary(self.repo_root),
            llm_comparison_summary=_llm_comparison_summary(self.repo_root),
            generated_at=datetime.now(timezone.utc).isoformat(),
            environment={
                "python": platform.python_version(),
                "platform": platform.system(),
                "profile": settings.vulnagent_profile,
                "default_llm_provider": settings.llm_provider,
                "storage_backend": settings.storage_backend,
            },
            notices=list(_NOTICES),
            groups=groups,
        )

    def _benchmark_version(self) -> str:
        source_manifest = _read_json(self.repo_root / "benchmarks" / "manifest.json")
        if isinstance(source_manifest, dict):
            version = source_manifest.get("schema_version")
            if isinstance(version, str):
                return version
        return "1.1"
