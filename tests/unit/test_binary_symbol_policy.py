"""Focused tests for conservative binary symbol classification."""

from vulnagent.agents.binary_analysis_agent import BinaryAnalysisAgent


def test_explicit_and_decorated_risky_symbols_are_detected() -> None:
    matches = BinaryAnalysisAgent._risky_symbols(
        ["KERNEL32.dll!system", "msvcrt.dll!__imp_strcpy"],
        ["ucrt_sprintf.c", "calls scanf for input"],
    )

    assert matches == ["scanf", "sprintf", "strcpy", "system"]


def test_bounded_and_ambiguous_runtime_symbols_are_not_risky() -> None:
    matches = BinaryAnalysisAgent._risky_symbols(
        ["api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vsprintf"],
        ["snprintf", "strcpy_s", "systematic analysis"],
    )

    assert matches == []


def test_explicit_vsprintf_remains_a_risky_signal() -> None:
    assert BinaryAnalysisAgent._risky_symbols([], ["vsprintf"]) == ["vsprintf"]


def test_only_versioned_high_confidence_unbounded_callsites_are_selected() -> None:
    metadata = {
        "callsite_semantics": {
            "schema_version": 1,
            "analyzer": "pe-x64-callsite-semantics",
            "available": True,
            "target_executed": False,
            "callsites": [
                {
                    "classification": "unbounded_format_write",
                    "inferred_api": "sprintf",
                    "confidence": 0.9,
                },
                {
                    "classification": "bounded_count_shape",
                    "inferred_api": None,
                    "confidence": 0.6,
                },
            ],
        }
    }

    assert BinaryAnalysisAgent._risky_callsites(metadata) == [
        metadata["callsite_semantics"]["callsites"][0]
    ]


def test_untrusted_or_low_confidence_callsite_metadata_is_ignored() -> None:
    low_confidence = {
        "callsite_semantics": {
            "schema_version": 1,
            "analyzer": "pe-x64-callsite-semantics",
            "available": True,
            "target_executed": False,
            "callsites": [
                {
                    "classification": "unbounded_format_write",
                    "inferred_api": "sprintf",
                    "confidence": 0.5,
                }
            ],
        }
    }
    executed = {
        **low_confidence,
        "callsite_semantics": {
            **low_confidence["callsite_semantics"],
            "target_executed": True,
        },
    }

    assert BinaryAnalysisAgent._risky_callsites(low_confidence) == []
    assert BinaryAnalysisAgent._risky_callsites(executed) == []
