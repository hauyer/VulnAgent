"""Scope and credential-safety tests for the V0.4 demo bundle."""

import hashlib
import json
from pathlib import Path

import pytest

from scripts.demo_v04 import (
    _reject_sensitive_fields,
    collect_experiment_snapshots,
    collect_protected_benchmark,
    collect_protected_readiness,
    render_summary,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _manifest(root: Path, relative: str, content: str) -> str:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return hashlib.sha256(content.encode()).hexdigest()


def test_snapshots_keep_paid_prior_scope_separate(tmp_path: Path) -> None:
    current_hash = _manifest(tmp_path, "benchmarks/manifest.json", '{"version": 2}')
    _manifest(tmp_path, "benchmarks/binary/manifest.json", "{}")
    _manifest(tmp_path, "benchmarks/fuzz/manifest.json", "{}")
    _manifest(tmp_path, "benchmarks/elf/manifest.json", "{}")
    source_dir = tmp_path / "artifacts/experiments/source-ablation"
    _write_json(source_dir / "run_manifest.json", {"manifest_sha256": current_hash})
    _write_json(source_dir / "metrics.json", [{"method": "full", "samples": 20}])
    llm_dir = tmp_path / "artifacts/experiments/llm-comparison"
    _write_json(llm_dir / "run_manifest.json", {"manifest_sha256": "older"})
    _write_json(llm_dir / "metrics.json", [{"method": "llm", "samples": 12}])

    snapshots = collect_experiment_snapshots(tmp_path)

    assert snapshots["source_ablation"]["status"] == "current"
    assert snapshots["llm_comparison"]["status"] == "frozen_prior_scope"
    assert snapshots["llm_comparison"]["external_call_started"] is False
    assert snapshots["elf_benchmark"]["status"] == "not_run"


def test_sensitive_fields_are_rejected_without_echoing_value() -> None:
    with pytest.raises(ValueError, match="provider.api_key") as error:
        _reject_sensitive_fields({"provider": {"api_key": "do-not-copy"}})

    assert "do-not-copy" not in str(error.value)

    with pytest.raises(ValueError, match="auth.access_token"):
        _reject_sensitive_fields({"auth": {"access_token": "do-not-copy"}})


def test_public_llm_metering_fields_are_not_treated_as_credentials() -> None:
    _reject_sensitive_fields(
        {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "total_tokens": 120,
            "token_cost": 0.01,
            "token_cost_currency": "CNY",
        }
    )


def test_protected_readiness_rejects_stale_scope(tmp_path: Path) -> None:
    packed_hash = _manifest(tmp_path, "benchmarks/packed/manifest.json", '{"kind":"packing"}')
    _manifest(tmp_path, "benchmarks/obfuscated/manifest.json", '{"kind":"obfuscation"}')
    _write_json(
        tmp_path / "artifacts/experiments/protected-readiness/readiness.json",
        {
            "strict_requirement_met": True,
            "ready_distinct_software": {"packing": 2, "obfuscation": 2},
            "target_execution": False,
            "manifests": [
                {"protection_kind": "packing", "sha256": packed_hash},
                {"protection_kind": "obfuscation", "sha256": "older"},
            ],
        },
    )

    result = collect_protected_readiness(tmp_path)

    assert result["status"] == "stale"
    assert result["manifest_scope_matches_current"] is False


def test_protected_benchmark_requires_current_manifest_scope(tmp_path: Path) -> None:
    packed_hash = _manifest(tmp_path, "benchmarks/packed/manifest.json", "packed")
    obfuscated_hash = _manifest(
        tmp_path, "benchmarks/obfuscated/manifest.json", "obfuscated"
    )
    output = tmp_path / "artifacts/experiments/protected-benchmark"
    _write_json(
        output / "metrics.json",
        {
            "sample_count": 4,
            "static_signal_observed_count": 4,
            "pipeline_completed_count": 4,
            "pseudocode_available_count": 3,
            "evidence_chain_complete_count": 4,
            "target_execution_count": 0,
        },
    )
    _write_json(
        output / "run_manifest.json",
        {"manifests": [{"sha256": packed_hash}, {"sha256": obfuscated_hash}]},
    )

    result = collect_protected_benchmark(tmp_path)

    assert result["status"] == "current"
    assert result["sample_count"] == 4
    assert result["target_execution_count"] == 0


def test_summary_states_llm_and_elf_boundaries() -> None:
    bundle = {
        "generated_at": "2026-09-11T00:00:00Z",
        "live_demo": {
            name: {
                "status": "completed",
                "finding_count": 1,
                "confirmed_count": 1,
                "target_executed": name == "fuzz",
            }
            for name in ("source", "binary", "fuzz")
        },
        "experiments": {
            "llm_comparison": {
                "status": "frozen_prior_scope",
                "metrics": [],
            },
            "elf_benchmark": {"status": "current", "metrics": []},
        },
        "protected_readiness": {
            "status": "current",
            "strict_requirement_met": True,
            "ready_distinct_software": {"packing": 2, "obfuscation": 2},
        },
        "protected_benchmark": {
            "status": "current",
            "sample_count": 4,
            "static_signal_observed_count": 4,
            "pipeline_completed_count": 4,
            "pseudocode_available_count": 3,
            "evidence_chain_complete_count": 4,
            "target_execution_count": 0,
        },
        "artifacts": {
            "source_html": "source.html",
            "source_pdf": "source.pdf",
            "llm_comparison_summary": "../../llm/summary.md",
            "protected_benchmark_summary": "../../protected/summary.md",
            "elf_benchmark_summary": "../../elf/summary.md",
        },
    }

    summary = render_summary(bundle)

    assert "不会调用外部 LLM" in summary
    assert "frozen_prior_scope" in summary
    assert "ELF" in summary and "current" in summary
    assert "严格课程要求已满足" in summary
    assert "Part 6B" in summary
    assert "[HTML](source.html)" in summary
    assert "[PDF](source.pdf)" in summary
    assert "[LLM Usage/Cost 汇总](../../llm/summary.md)" in summary
    assert "[Part 6B 受保护样本汇总](../../protected/summary.md)" in summary
    assert "[真实 ELF Benchmark 汇总](../../elf/summary.md)" in summary
