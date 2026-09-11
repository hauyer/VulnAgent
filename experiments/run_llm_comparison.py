"""Compare configured LLM-only baselines with the evidence-first system."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import platform
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from experiments.run_metrics import calculate_metrics, write_metrics
from experiments.run_source_ablation import load_manifest, run_suite as run_source_suite
from vulnagent.llm.base import BaseLLM
from vulnagent.llm.router import LLMRouter
from vulnagent.settings import Settings


LOGGER = logging.getLogger(__name__)
_MAX_SAMPLE_BYTES = 32 * 1024


def render_summary(
    metrics: list[dict[str, Any]], run_manifest: dict[str, Any]
) -> str:
    """Render a presentation-ready accuracy, usage, and cost summary."""

    lines = [
        "# VulnAgent V0.4 LLM 对比与 Usage/Cost",
        "",
        f"> 生成时间：{run_manifest['generated_at']}",
        "> Token 来自供应商 Chat Completions 响应；费用按 run manifest 中的版本化费率估算，并非账户最终账单。",
        "",
        "| 方法 | 样本 | TP/FP/TN/FN | Precision | Recall | F1 | Prompt | Completion | Total | 估算费用 | Evidence |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for metric in metrics:
        currency = metric.get("token_cost_currency") or ""
        cost = metric.get("total_token_cost")
        cost_text = f"{cost:.8f} {currency}" if isinstance(cost, (int, float)) else "—"
        lines.append(
            "| {method} | {samples} | {tp}/{fp}/{tn}/{fn} | {precision:.3f} | "
            "{recall:.3f} | {f1:.3f} | {prompt} | {completion} | {total} | "
            "{cost} | {evidence:.3f} |".format(
                method=metric.get("method", "unknown"),
                samples=metric.get("samples", 0),
                tp=metric.get("true_positive", 0),
                fp=metric.get("false_positive", 0),
                tn=metric.get("true_negative", 0),
                fn=metric.get("false_negative", 0),
                precision=float(metric.get("precision", 0)),
                recall=float(metric.get("recall", 0)),
                f1=float(metric.get("f1", 0)),
                prompt=metric.get("prompt_tokens") or "—",
                completion=metric.get("completion_tokens") or "—",
                total=metric.get("total_tokens") or "—",
                cost=cost_text,
                evidence=float(metric.get("evidence_chain_coverage", 0)),
            )
        )
    lines.extend(
        [
            "",
            "## 边界",
            "",
            "- 不保存 API Key、原始响应或模型私有推理；只保存公开摘要、响应哈希和运营指标。",
            "- 不同供应商币种不相加；费用估算依据运行时记录的每百万 Token 单价。",
            "- Full 系统默认使用确定性分析链，因此其 Token/Cost 为不可用，而不是伪造为 0。",
            "- LLM-only Evidence Coverage 为 0；分类点估计相同不代表它拥有 Evidence/Verification 闭环。",
            "",
        ]
    )
    return "\n".join(lines)


def _resolve_sample(root: Path, relative_path: str) -> Path:
    path = (root / relative_path).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"sample escapes repository root: {relative_path}")
    if not path.exists():
        raise FileNotFoundError(f"sample does not exist: {path}")
    return path


def _source_text(path: Path) -> str:
    files = [path] if path.is_file() else sorted(path.rglob("*.py"))
    chunks: list[str] = []
    total = 0
    for file in files:
        if not file.is_file():
            continue
        data = file.read_bytes()
        remaining = _MAX_SAMPLE_BYTES - total
        if remaining <= 0:
            break
        data = data[:remaining]
        total += len(data)
        chunks.append(
            f"# file: {file.relative_to(path if path.is_dir() else path.parent).as_posix()}\n"
            + data.decode("utf-8", errors="replace")
        )
    if not chunks:
        raise ValueError(f"sample has no readable Python files: {path}")
    return "\n\n".join(chunks)


def _prompt(sample_id: str, source: str) -> str:
    return json.dumps(
        {
            "task": "classify the supplied authorized teaching source sample",
            "sample_id": sample_id,
            "source_code": source,
            "output_schema": {
                "verdict": "vulnerable or clean",
                "finding_types": ["short vulnerability type labels"],
                "confidence": "number from 0 to 1",
                "summary": "one short public rationale without chain-of-thought",
            },
            "constraints": [
                "return JSON only",
                "do not execute code",
                "do not generate exploit payloads",
            ],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _parse_response(response: str) -> dict[str, Any]:
    parsed = json.loads(response)
    if not isinstance(parsed, dict):
        raise ValueError("model response must be a JSON object")
    verdict = str(parsed.get("verdict", "")).strip().casefold()
    if verdict not in {"vulnerable", "clean"}:
        raise ValueError("model verdict must be vulnerable or clean")
    raw_types = parsed.get("finding_types", [])
    finding_types = (
        [str(item)[:80] for item in raw_types[:16]]
        if isinstance(raw_types, list)
        else []
    )
    raw_confidence = parsed.get("confidence")
    confidence = float(raw_confidence) if raw_confidence is not None else None
    if confidence is not None and not 0.0 <= confidence <= 1.0:
        raise ValueError("model confidence must be between 0 and 1")
    return {
        "verdict": verdict,
        "finding_types": finding_types,
        "confidence": confidence,
        "summary": str(parsed.get("summary") or "")[:500],
    }


async def run_suite(
    manifest_path: Path,
    providers: Mapping[str, BaseLLM],
    *,
    repo_root: Path | None = None,
    max_samples: int | None = None,
    include_full: bool = True,
) -> list[dict[str, Any]]:
    """Run provider baselines sequentially, plus the full system if requested."""
    if len(providers) < 2:
        raise ValueError("LLM comparison requires at least two configured providers")
    manifest = load_manifest(manifest_path)
    root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
    samples = list(manifest["samples"])
    if max_samples is not None:
        if max_samples <= 0:
            raise ValueError("max_samples must be positive")
        samples = samples[:max_samples]
    rows: list[dict[str, Any]] = []

    for sample in samples:
        path = _resolve_sample(root, str(sample["path"]))
        source = _source_text(path)
        prompt = _prompt(str(sample["sample_id"]), source)
        for provider_name, provider in providers.items():
            started = perf_counter()
            completion = await provider.generate_with_usage(
                prompt,
                system_prompt=(
                    "You are a source-security classifier. Return only the "
                    "requested compact JSON verdict."
                ),
                max_tokens=512,
                temperature=0.0,
                response_format={"type": "json_object"},
                thinking={"type": "disabled"},
            )
            elapsed = perf_counter() - started
            response = completion.text
            usage = completion.usage
            parsed = _parse_response(response)
            rows.append(
                {
                    "sample_id": sample["sample_id"],
                    "family_id": sample.get("family_id"),
                    "difficulty": sample.get("difficulty"),
                    "method": f"llm_only:{provider_name}",
                    "expected": sample["ground_truth"],
                    "observed": parsed["verdict"],
                    "duration_seconds": elapsed,
                    "agent_steps": 1,
                    "prompt_tokens": usage.prompt_tokens,
                    "completion_tokens": usage.completion_tokens,
                    "total_tokens": usage.total_tokens,
                    "cached_prompt_tokens": usage.cached_prompt_tokens,
                    "token_cost": usage.cost,
                    "token_cost_currency": usage.currency,
                    "token_cost_is_estimate": usage.cost_is_estimate,
                    "usage_available": usage.available,
                    "coverage": None,
                    "crashes": 0,
                    "unique_crashes": 0,
                    "confirmed_findings": 0,
                    "uncertain_findings": 0,
                    "evidence_complete": False,
                    "finding_types": parsed["finding_types"],
                    "model_confidence": parsed["confidence"],
                    "model_summary": parsed["summary"],
                    "raw_response_sha256": hashlib.sha256(
                        response.encode("utf-8")
                    ).hexdigest(),
                }
            )

    if include_full:
        full_rows = await run_source_suite(manifest_path, repo_root=root)
        allowed_ids = {str(sample["sample_id"]) for sample in samples}
        rows.extend(
            row
            for row in full_rows
            if row["method"] == "vulnagent_full"
            and str(row["sample_id"]) in allowed_ids
        )
    return rows


def _providers(names: Sequence[str], settings: Settings) -> dict[str, BaseLLM]:
    router = LLMRouter.from_settings(settings)
    normalized = [name.strip().casefold() for name in names]
    if len(set(normalized)) < 2:
        raise ValueError("select at least two distinct LLM providers")
    return {name: router.get(name) for name in normalized}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare two or more real LLM-only baselines with VulnAgent."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--providers", nargs="+", default=["deepseek", "glm"])
    parser.add_argument("--max-samples", type=int)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = Settings()
    providers = _providers(args.providers, settings)
    manifest_path = args.manifest.resolve()
    run_started_at = datetime.now(timezone.utc).isoformat()
    rows = asyncio.run(
        run_suite(
            manifest_path,
            providers,
            max_samples=args.max_samples,
        )
    )
    run_completed_at = datetime.now(timezone.utc).isoformat()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "labelled_results.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    metrics = calculate_metrics(rows)
    write_metrics(metrics, output_dir)
    run_manifest = {
        "generated_at": run_completed_at,
        "run_started_at": run_started_at,
        "run_completed_at": run_completed_at,
        "manifest_path": str(manifest_path),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "providers": {
            name: {
                "adapter": type(provider).__name__,
                "model": provider.model,
                "request_controls": {
                    "fixed_temperature": getattr(
                        provider, "fixed_temperature", None
                    ),
                    "min_request_interval_seconds": getattr(
                        provider, "min_request_interval_seconds", 0.0
                    ),
                    "rate_limit_retry_delays_seconds": list(
                        getattr(provider, "rate_limit_retry_delays", ())
                    ),
                },
                "pricing": (
                    {
                        "input_per_million": provider.pricing.input_per_million,
                        "cached_input_per_million": provider.pricing.cached_input_per_million,
                        "output_per_million": provider.pricing.output_per_million,
                        "currency": provider.pricing.currency,
                        "source_url": provider.pricing.source_url,
                        "effective_date": provider.pricing.effective_date,
                        "rate_label": provider.pricing.rate_label,
                        "values_are_estimates": True,
                    }
                    if getattr(provider, "pricing", None) is not None
                    else None
                ),
            }
            for name, provider in providers.items()
        },
        "sample_count": len({str(row["sample_id"]) for row in rows}),
        "python": platform.python_version(),
        "secrets_recorded": False,
        "usage_source": "provider_chat_completion_response",
    }
    (output_dir / "run_manifest.json").write_text(
        json.dumps(run_manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (output_dir / "summary.md").write_text(
        render_summary(metrics, run_manifest), encoding="utf-8"
    )
    LOGGER.info("Completed LLM comparison; artifacts written to %s", output_dir)


if __name__ == "__main__":
    main()
