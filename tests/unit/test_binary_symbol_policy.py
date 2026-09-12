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


def test_common_file_system_text_is_not_treated_as_system_call() -> None:
    matches = BinaryAnalysisAgent._risky_symbols(
        [],
        ["read only file system", "too many files open in system"],
    )

    assert matches == []


def test_decompiled_system_call_remains_detectable() -> None:
    matches = BinaryAnalysisAgent._risky_symbols(
        [],
        ['int run(void) { return system("whoami"); }'],
        allow_embedded_text=True,
    )

    assert matches == ["system"]


def test_decompiled_string_comment_does_not_become_system_call() -> None:
    matches = BinaryAnalysisAgent._risky_symbols(
        [],
        ['puts("read only file system");'],
        allow_embedded_text=True,
    )

    assert matches == []


def test_explicit_vsprintf_remains_a_risky_signal() -> None:
    assert BinaryAnalysisAgent._risky_symbols([], ["vsprintf"]) == ["vsprintf"]


def test_binary_locator_uses_import_table_address_without_claiming_source_line() -> None:
    from vulnagent.contracts import BinaryAnalysisResult

    result = BinaryAnalysisResult(
        task_id="task",
        target_id="target",
        path="sample.exe",
        metadata={
            "format_details": {
                "import_entries": [
                    {
                        "dll": "msvcrt.dll",
                        "symbol": "strcpy",
                        "iat_address": 0x140003000,
                    }
                ]
            }
        },
    )

    locator = BinaryAnalysisAgent._binary_locator(
        result,
        {},
        [],
        ["strcpy"],
        [],
    )

    assert locator == {
        "binary_address": "0x140003000",
        "function_name": None,
        "located_symbol": "strcpy",
        "locator_kind": "import_table",
        "locator_precision": "iat_address",
    }


def test_binary_locator_uses_decoded_callsite_and_enclosing_function() -> None:
    from vulnagent.contracts import BinaryAnalysisResult

    result = BinaryAnalysisResult(
        task_id="task",
        target_id="target",
        path="sample.exe",
    )
    locator = BinaryAnalysisAgent._binary_locator(
        result,
        {},
        [{"address": 0x401020, "inferred_api": "sprintf"}],
        ["sprintf"],
        [{"name": "render", "address": 0x401000, "size": 0x80}],
    )

    assert locator["binary_address"] == "0x401020"
    assert locator["function_name"] == "render"
    assert locator["locator_kind"] == "decoded_callsite"
    assert locator["locator_precision"] == "instruction_address"


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
