"""Acceptance matrix status calculation across honest on-disk transitions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from vulnagent.acceptance import (
    AcceptanceCalculator,
    AcceptanceStatus,
)
from vulnagent.settings import Settings


def _settings(**overrides: Any) -> Settings:
    return Settings(_env_file=None, **overrides)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _sample(sample_id: str, name: str, kind: str, sha256: str = "a" * 64) -> dict[str, Any]:
    return {
        "sample_id": sample_id,
        "software": {"name": name, "author": "author", "version": "1.0"},
        "protection": {
            "kind": kind,
            "product": "protector",
            "secondary": "secondary-method",
        },
        "provenance": {"source_uri": "https://example.invalid/sample"},
        "authorization": {
            "static_analysis": True,
            "tool_transform": True,
            "dynamic_execution": False,
        },
        "local_path": f"materials/{sample_id}.bin",
        "sha256": sha256,
        "file_format": "PE",
        "architecture": "x86-64",
    }


def _write_manifests(root: Path) -> None:
    packed = {
        "schema_version": "1.1",
        "protection_kind": "packing",
        "samples": [_sample("p1", "Packed One", "packing"), _sample("p2", "Packed Two", "packing")],
    }
    _write_json(root / "benchmarks" / "packed" / "manifest.json", packed)
    obfuscated = {
        "schema_version": "1.1",
        "protection_kind": "obfuscation",
        "samples": [
            _sample("o1", "Obfuscated One", "obfuscation"),
            _sample("o2", "Obfuscated Two", "obfuscation"),
        ],
    }
    _write_json(root / "benchmarks" / "obfuscated" / "manifest.json", obfuscated)
    _write_json(
        root / "benchmarks" / "manifest.json",
        {"schema_version": "1.1", "samples": [{"sample_id": f"src-{i}"} for i in range(20)]},
    )
    _write_json(
        root / "benchmarks" / "binary" / "manifest.json",
        {"schema_version": "1.1", "samples": [{"sample_id": f"bin-{i}"} for i in range(14)]},
    )
    _write_json(
        root / "benchmarks" / "fuzz" / "manifest.json",
        {"schema_version": "1.1", "samples": [{"sample_id": "fuzz-0"}]},
    )


def _analysis_rows() -> list[dict[str, Any]]:
    return [
        {
            "sample_id": "p1",
            "protection_kind": "packing",
            "pipeline": {"finding_count": 0, "finding_status_counts": {}, "evidence_chain_complete": True},
        },
        {
            "sample_id": "p2",
            "protection_kind": "packing",
            "pipeline": {"finding_count": 0, "finding_status_counts": {}, "evidence_chain_complete": True},
        },
    ]


def test_no_providers_blocks_llm_group(tmp_path: Path) -> None:
    _write_manifests(tmp_path)
    overview = AcceptanceCalculator(repo_root=tmp_path).build_overview(_settings())
    group_a = overview.groups[0]
    assert group_a.status is AcceptanceStatus.BLOCKED
    assert overview.passed_groups == 0
    assert overview.status_text == "0/3"


def test_configured_providers_without_run_is_not_run(tmp_path: Path) -> None:
    _write_manifests(tmp_path)
    settings = _settings(deepseek_api_key="k", glm_api_key="k")
    overview = AcceptanceCalculator(repo_root=tmp_path).build_overview(settings)
    group_a = overview.groups[0]
    assert group_a.status is AcceptanceStatus.NOT_RUN
    configured = [p for p in group_a.providers if p.configured]
    assert sorted(p.provider for p in configured) == ["deepseek", "glm"]


def test_benchmark_summary_exposes_inventory_and_stripped_metrics(tmp_path: Path) -> None:
    _write_manifests(tmp_path)
    _write_json(
        tmp_path / "artifacts" / "experiments" / "binary-benchmark" / "metrics.json",
        [
            {
                "method": "vulnagent_binary_stripped",
                "samples": 14,
                "true_positive": 7,
                "false_positive": 0,
                "true_negative": 7,
                "false_negative": 0,
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
                "false_positive_rate": 0.0,
                "evidence_chain_coverage": 1.0,
            }
        ],
    )
    _write_json(
        tmp_path / "artifacts" / "experiments" / "binary-benchmark" / "run_manifest.json",
        {"generated_at": "2026-09-12T08:00:00+00:00"},
    )
    _write_json(
        tmp_path / "artifacts" / "experiments" / "elf-benchmark" / "metrics.json",
        [
            {
                "method": f"vulnagent_elf_{method}",
                "samples": 6,
                "true_positive": 3,
                "false_positive": 0,
                "true_negative": 3,
                "false_negative": 0,
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
                "evidence_chain_coverage": 1.0,
            }
            for method in ("symbol_rich", "stripped", "pie")
        ],
    )
    _write_json(
        tmp_path / "artifacts" / "experiments" / "elf-benchmark" / "run_manifest.json",
        {
            "fixture_count": 6,
            "family_count": 3,
            "row_count": 18,
            "compiler_version": "0.16.0",
            "compiler_machine": "x86_64-linux-gnu",
            "target_execution": False,
            "generated_at": "2026-09-12T08:05:00+00:00",
        },
    )

    overview = AcceptanceCalculator(repo_root=tmp_path).build_overview(_settings())
    counts = overview.benchmark_summary.counts
    assert (counts.source_samples, counts.binary_samples, counts.fuzz_scenarios) == (20, 14, 1)
    stripped = overview.benchmark_summary.stripped_binary
    assert stripped is not None
    assert stripped.samples == 14
    assert stripped.recall == pytest.approx(1.0)
    assert stripped.f1 == pytest.approx(1.0)
    assert stripped.generated_at == "2026-09-12T08:00:00+00:00"
    elf_a = overview.benchmark_summary.elf_a
    assert elf_a is not None
    assert (elf_a.fixture_count, elf_a.profile_count, elf_a.row_count) == (6, 3, 18)
    assert elf_a.compiler_machine == "x86_64-linux-gnu"
    assert elf_a.target_execution is False
    assert [item.profile for item in elf_a.profiles] == ["symbol-rich", "stripped", "pie"]
    assert all(item.f1 == pytest.approx(1.0) for item in elf_a.profiles)


def test_published_llm_baseline_is_display_only_fallback(tmp_path: Path) -> None:
    _write_manifests(tmp_path)
    manifest_hash = hashlib.sha256(
        (tmp_path / "benchmarks" / "manifest.json").read_bytes()
    ).hexdigest()
    _write_json(
        tmp_path / "benchmarks" / "baselines" / "llm-comparison-v04.json",
        {
            "snapshot_id": "published-test",
            "benchmark_manifest_sha256": manifest_hash,
            "metrics": [
                {
                    "method": "llm_only:kimi",
                    "samples": 20,
                    "precision": 1.0,
                    "recall": 1.0,
                    "f1": 1.0,
                    "total_tokens": 4696,
                    "total_token_cost": 0.0347383,
                    "token_cost_currency": "CNY",
                }
            ],
        },
    )

    overview = AcceptanceCalculator(repo_root=tmp_path).build_overview(_settings())
    summary = overview.llm_comparison_summary
    assert summary.source == "published_baseline"
    assert summary.snapshot_id == "published-test"
    assert summary.manifest_matches is True
    assert summary.metrics[0].method == "llm_only:kimi"
    assert summary.metrics[0].total_tokens == 4696
    # A published baseline is display-only and never changes current-run acceptance.
    assert overview.groups[0].status is AcceptanceStatus.BLOCKED


def test_llm_comparison_reaches_partial(tmp_path: Path) -> None:
    _write_manifests(tmp_path)
    metrics = [
        {
            "method": "llm_only:deepseek",
            "samples": 20,
            "true_positive": 10,
            "false_positive": 0,
            "true_negative": 10,
            "false_negative": 0,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "total_tokens": 5248,
            "total_token_cost": 0.002317218,
            "token_cost_currency": "USD",
            "evidence_chain_coverage": 0.0,
        },
        {
            "method": "llm_only:glm",
            "samples": 20,
            "true_positive": 10,
            "false_positive": 0,
            "true_negative": 10,
            "false_negative": 0,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "total_tokens": 5803,
            "total_token_cost": 0.069904,
            "token_cost_currency": "CNY",
            "evidence_chain_coverage": 0.0,
        },
        {"method": "vulnagent_full", "samples": 20, "confirmed_finding_count": 10},
    ]
    _write_json(tmp_path / "artifacts" / "experiments" / "llm-comparison" / "metrics.json", metrics)
    _write_json(
        tmp_path / "artifacts" / "experiments" / "llm-comparison" / "run_manifest.json",
        {"sample_count": 20, "providers": {"deepseek": {"model": "deepseek-v4-flash"}}},
    )
    settings = _settings(deepseek_api_key="k", glm_api_key="k")
    overview = AcceptanceCalculator(repo_root=tmp_path).build_overview(settings)
    group_a = overview.groups[0]
    assert group_a.status is AcceptanceStatus.PARTIAL
    conditions = {item.key: item.met for item in group_a.conditions}
    assert conditions["comparison_run"] is True
    assert conditions["independent_verification"] is True
    assert conditions["controlled_exploit_verification"] is False
    comparison = {item.method: item for item in group_a.comparison}
    assert set(comparison) == {"llm_only:deepseek", "llm_only:glm", "vulnagent_full"}
    assert comparison["llm_only:deepseek"].total_tokens == 5248
    assert comparison["llm_only:deepseek"].token_cost_currency == "USD"
    assert comparison["llm_only:glm"].total_token_cost == pytest.approx(0.069904)
    assert comparison["vulnagent_full"].confirmed_finding_count == 10


def test_protected_analysis_reaches_partial(tmp_path: Path) -> None:
    _write_manifests(tmp_path)
    _write_json(
        tmp_path / "artifacts" / "experiments" / "protected-benchmark" / "analysis_results.json",
        _analysis_rows(),
    )
    _write_json(
        tmp_path / "artifacts" / "experiments" / "protected-benchmark" / "metrics.json",
        {
            "sample_count": 2,
            "target_execution_count": 0,
            "vulnerability_ground_truth_available": False,
        },
    )
    overview = AcceptanceCalculator(repo_root=tmp_path).build_overview(_settings())
    group_b = next(g for g in overview.groups if g.group_id == "b")
    assert group_b.status is AcceptanceStatus.PARTIAL
    conditions = {item.key: item.met for item in group_b.conditions}
    assert conditions["static_analysis"] is True
    assert conditions["confirmed_finding"] is False
    assert conditions["ground_truth"] is False
    assert conditions["controlled_poc"] is False


def test_protected_pass_requires_gt_and_poc(tmp_path: Path) -> None:
    _write_manifests(tmp_path)
    rows = [
        {
            "sample_id": "p1",
            "protection_kind": "packing",
            "pipeline": {
                "finding_count": 1,
                "finding_status_counts": {"confirmed": 1},
                "evidence_chain_complete": True,
            },
        },
        {
            "sample_id": "p2",
            "protection_kind": "packing",
            "pipeline": {"finding_count": 0, "finding_status_counts": {}, "evidence_chain_complete": True},
        },
    ]
    _write_json(
        tmp_path / "artifacts" / "experiments" / "protected-benchmark" / "analysis_results.json",
        rows,
    )
    _write_json(
        tmp_path / "artifacts" / "experiments" / "protected-benchmark" / "metrics.json",
        {
            "sample_count": 2,
            "target_execution_count": 0,
            "vulnerability_ground_truth_available": True,
            "controlled_poc_evidence_available": True,
        },
    )
    overview = AcceptanceCalculator(repo_root=tmp_path).build_overview(_settings())
    group_b = next(g for g in overview.groups if g.group_id == "b")
    assert group_b.status is AcceptanceStatus.PASS


def test_material_present_but_not_run_is_not_run(tmp_path: Path) -> None:
    _write_manifests(tmp_path)
    # Build a real material file whose sha256 matches the packed manifest.
    material_dir = tmp_path / "benchmarks" / "packed" / "materials"
    material_dir.mkdir(parents=True, exist_ok=True)
    payload = b"fixture-binary"
    (material_dir / "p1.bin").write_bytes(payload)
    (material_dir / "p2.bin").write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    packed = {
        "schema_version": "1.1",
        "protection_kind": "packing",
        "samples": [
            _sample("p1", "Packed One", "packing", digest),
            _sample("p2", "Packed Two", "packing", digest),
        ],
    }
    _write_json(tmp_path / "benchmarks" / "packed" / "manifest.json", packed)
    overview = AcceptanceCalculator(repo_root=tmp_path).build_overview(_settings())
    group_b = next(g for g in overview.groups if g.group_id == "b")
    assert group_b.status is AcceptanceStatus.NOT_RUN
    assert all(target.intake_ready for target in group_b.targets)
    assert all(target.protector_secondary == "secondary-method" for target in group_b.targets)


def test_empty_cost_string_is_coerced_to_none() -> None:
    settings = _settings(
        deepseek_api_key="k",
        deepseek_input_cost_per_million="",
        deepseek_output_cost_per_million="",
    )
    assert settings.deepseek_input_cost_per_million is None
    assert settings.deepseek_output_cost_per_million is None


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
