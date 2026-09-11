import json

import pytest

from experiments.run_metrics import calculate_metrics, load_rows


def test_metrics_include_classification_and_operational_signals() -> None:
    rows = [
        {
            "method": "full",
            "expected": "vulnerable",
            "observed": "vulnerable",
            "duration_seconds": 1.0,
            "evidence_complete": True,
            "agent_steps": 5,
            "confirmed_findings": 2,
            "uncertain_findings": 1,
            "coverage": 0.5,
            "crashes": 2,
            "unique_crashes": 1,
            "usage_available": True,
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "total_tokens": 120,
            "cached_prompt_tokens": 10,
            "token_cost": 0.01,
            "token_cost_currency": "CNY",
        },
        {
            "method": "full",
            "expected": "clean",
            "observed": "vulnerable",
            "duration_seconds": 3.0,
            "evidence_complete": False,
            "agent_steps": 7,
            "confirmed_findings": 1,
            "coverage": 1.0,
            "usage_available": True,
            "prompt_tokens": 200,
            "completion_tokens": 30,
            "total_tokens": 230,
            "cached_prompt_tokens": 20,
            "token_cost": 0.02,
            "token_cost_currency": "CNY",
        },
    ]

    result = calculate_metrics(rows)[0]

    assert result["precision"] == 0.5
    assert result["recall"] == 1.0
    assert result["evidence_chain_coverage"] == 0.5
    assert result["mean_duration_seconds"] == 2.0
    assert result["mean_agent_steps"] == 6.0
    assert result["mean_coverage"] == 0.75
    assert result["confirmed_finding_count"] == 3
    assert result["uncertain_finding_count"] == 1
    assert result["crash_count"] == 2
    assert result["unique_crash_count"] == 1
    assert result["usage_available_count"] == 2
    assert result["prompt_tokens"] == 300
    assert result["completion_tokens"] == 50
    assert result["total_tokens"] == 350
    assert result["cached_prompt_tokens"] == 30
    assert result["total_token_cost"] == pytest.approx(0.03)
    assert result["mean_token_cost"] == pytest.approx(0.015)
    assert result["token_cost_currency"] == "CNY"
    assert 0.0 <= result["precision_ci95_low"] <= result["precision"]
    assert result["precision"] <= result["precision_ci95_high"] <= 1.0


def test_invalid_labels_are_rejected() -> None:
    with pytest.raises(ValueError, match="invalid observed label"):
        calculate_metrics(
            [{"method": "full", "expected": "clean", "observed": "maybe"}]
        )


def test_unique_crashes_are_deduplicated_across_trials() -> None:
    result = calculate_metrics(
        [
            {
                "method": "guided",
                "expected": "vulnerable",
                "observed": "vulnerable",
                "crashes": 1,
                "crash_fingerprints": ["same-crash"],
            },
            {
                "method": "guided",
                "expected": "vulnerable",
                "observed": "vulnerable",
                "crashes": 1,
                "crash_fingerprints": ["same-crash"],
            },
        ]
    )[0]

    assert result["crash_count"] == 2
    assert result["unique_crash_count"] == 1


def test_json_lines_input_is_supported(tmp_path) -> None:
    path = tmp_path / "rows.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(row)
            for row in [
                {"method": "a", "expected": "clean", "observed": "clean"},
                {
                    "method": "a",
                    "expected": "vulnerable",
                    "observed": "vulnerable",
                },
            ]
        ),
        encoding="utf-8",
    )

    assert len(load_rows(path)) == 2
