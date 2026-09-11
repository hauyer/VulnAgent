"""Tests for protected benchmark aggregation without invoking external tools."""

from experiments.run_protected_benchmark import calculate_summary, render_summary


def _row(kind: str, status: str = "uncertain") -> dict[str, object]:
    return {
        "protection_kind": kind,
        "software": {"name": f"{kind} sample", "author": "author"},
        "protection": {"product": "custom"},
        "static_signals": {"observed": True},
        "tools": {
            "radare2_inspection": {"pseudocode_count": 1},
            "transform": {"status": "not_requested"},
        },
        "pipeline": {
            "status": "completed",
            "finding_count": 1,
            "finding_status_counts": {status: 1},
            "evidence_chain_complete": True,
            "reports": {
                "html": f"reports/{kind}.html",
                "pdf": f"reports/{kind}.pdf",
            },
        },
        "target_executed": False,
    }


def test_summary_does_not_invent_vulnerability_accuracy() -> None:
    rows = [_row("packing"), _row("obfuscation")]
    summary = calculate_summary(rows, {"strict_requirement_met": True})

    assert summary["strict_intake_met"] is True
    assert summary["static_signal_observed_count"] == 2
    assert summary["target_execution_count"] == 0
    assert summary["vulnerability_ground_truth_available"] is False
    assert summary["precision_recall_reported"] is False

    markdown = render_summary(rows, summary)
    assert "不计算 Precision/Recall" in markdown
    assert "[HTML](reports/packing.html)" in markdown
    assert "[PDF](reports/obfuscation.pdf)" in markdown
