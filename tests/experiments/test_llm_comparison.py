"""Two-provider comparison harness without external network calls."""

import json
from pathlib import Path

import pytest

from experiments.run_llm_comparison import _parse_response, render_summary, run_suite
from vulnagent.llm.base import BaseLLM, LLMResponse, LLMUsage


class FixtureClassifier(BaseLLM):
    def __init__(self, label: str) -> None:
        self.label = label

    async def generate(self, prompt: str, **kwargs) -> str:
        assert kwargs["thinking"] == {"type": "disabled"}
        vulnerable = "eval(input())" in prompt
        return json.dumps(
            {
                "verdict": "vulnerable" if vulnerable else "clean",
                "finding_types": ["dynamic_code_execution"] if vulnerable else [],
                "confidence": 0.8,
                "summary": self.label,
            }
        )


class MeteredFixtureClassifier(FixtureClassifier):
    async def generate_with_usage(self, prompt: str, **kwargs) -> LLMResponse:
        return LLMResponse(
            text=await self.generate(prompt, **kwargs),
            usage=LLMUsage(
                prompt_tokens=120,
                completion_tokens=30,
                total_tokens=150,
                cached_prompt_tokens=20,
                cost=0.012,
                currency="CNY",
                cost_is_estimate=True,
            ),
        )


def _sample(sample_id: str, path: str, ground_truth: str) -> dict[str, object]:
    return {
        "sample_id": sample_id,
        "family_id": "llm-comparison-family",
        "difficulty": "hard",
        "path": path,
        "source": "self-authored test",
        "language": "python",
        "target_type": "source",
        "ground_truth": ground_truth,
        "cwe": ["CWE-95"] if ground_truth == "vulnerable" else [],
        "expected_findings": (
            ["dynamic_code_execution"] if ground_truth == "vulnerable" else []
        ),
        "authorization": "local self-authored fixture; static analysis only",
        "run_command": "pytest",
    }


@pytest.mark.asyncio
async def test_two_provider_harness_emits_labelled_rows(tmp_path: Path) -> None:
    vulnerable = tmp_path / "vulnerable"
    clean = tmp_path / "clean"
    vulnerable.mkdir()
    clean.mkdir()
    (vulnerable / "app.py").write_text("value = eval(input())\n", encoding="utf-8")
    (clean / "app.py").write_text("value = 1 + 1\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "samples": [
                    _sample("vulnerable", "vulnerable", "vulnerable"),
                    _sample("clean", "clean", "clean"),
                ]
            }
        ),
        encoding="utf-8",
    )

    rows = await run_suite(
        manifest,
        {
            "deepseek": FixtureClassifier("provider-a"),
            "glm": FixtureClassifier("provider-b"),
        },
        repo_root=tmp_path,
        include_full=False,
    )

    assert len(rows) == 4
    assert {row["method"] for row in rows} == {
        "llm_only:deepseek",
        "llm_only:glm",
    }
    assert all(row["expected"] == row["observed"] for row in rows)
    assert all(row["family_id"] == "llm-comparison-family" for row in rows)
    assert all(row["difficulty"] == "hard" for row in rows)
    assert all(row["evidence_complete"] is False for row in rows)
    assert all(len(row["raw_response_sha256"]) == 64 for row in rows)


@pytest.mark.asyncio
async def test_harness_records_provider_usage_without_response_body(tmp_path: Path) -> None:
    sample_dir = tmp_path / "sample"
    sample_dir.mkdir()
    (sample_dir / "app.py").write_text("value = 1 + 1\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"samples": [_sample("clean", "sample", "clean")]}),
        encoding="utf-8",
    )

    rows = await run_suite(
        manifest,
        {
            "provider-a": MeteredFixtureClassifier("a"),
            "provider-b": MeteredFixtureClassifier("b"),
        },
        repo_root=tmp_path,
        include_full=False,
    )

    assert all(row["usage_available"] is True for row in rows)
    assert all(row["prompt_tokens"] == 120 for row in rows)
    assert all(row["completion_tokens"] == 30 for row in rows)
    assert all(row["total_tokens"] == 150 for row in rows)
    assert all(row["token_cost"] == 0.012 for row in rows)
    assert all(row["token_cost_currency"] == "CNY" for row in rows)
    assert all("raw_response" not in row for row in rows)


def test_invalid_model_verdict_is_rejected() -> None:
    with pytest.raises(ValueError, match="verdict"):
        _parse_response('{"verdict":"maybe"}')


def test_usage_summary_keeps_currency_and_estimate_boundary() -> None:
    summary = render_summary(
        [
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
                "prompt_tokens": 4000,
                "completion_tokens": 1000,
                "total_tokens": 5000,
                "total_token_cost": 0.06,
                "token_cost_currency": "CNY",
                "evidence_chain_coverage": 0.0,
            }
        ],
        {"generated_at": "2026-09-11T00:00:00Z"},
    )

    assert "5000" in summary
    assert "0.06000000 CNY" in summary
    assert "并非账户最终账单" in summary
    assert "不同供应商币种不相加" in summary
