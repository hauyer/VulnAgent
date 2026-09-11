"""Unit tests for the obfuscation feature analyzer."""

from vulnagent.analyzers.binary.obfuscation import ObfuscationAnalyzer
from vulnagent.contracts import BinaryAnalysisResult


def _result(**kwargs) -> BinaryAnalysisResult:
    defaults = {"task_id": "t", "target_id": "x", "path": "a.exe"}
    defaults.update(kwargs)
    return BinaryAnalysisResult(**defaults)


async def test_empty_result_has_no_signals() -> None:
    out = await ObfuscationAnalyzer().inspect(_result())
    assert out["score"] == 0
    assert out["signals"] == []


async def test_detects_anti_debug_imports() -> None:
    out = await ObfuscationAnalyzer().inspect(_result(
        imports=["IsDebuggerPresent", "NtQueryInformationProcess"],
    ))
    assert "anti_debug_import" in {s["name"] for s in out["signals"]}


async def test_detects_packer_marker_strings() -> None:
    out = await ObfuscationAnalyzer().inspect(
        _result(strings=["UPX0", "Themida", "VmprotectBegin"])
    )
    assert "packer_marker_string" in {s["name"] for s in out["signals"]}


async def test_packer_marker_does_not_match_compression_identifier() -> None:
    out = await ObfuscationAnalyzer().inspect(
        _result(strings=["CompressionMode", "System.IO.Compression"])
    )
    assert "packer_marker_string" not in {s["name"] for s in out["signals"]}


async def test_detects_base64_string_obfuscation() -> None:
    out = await ObfuscationAnalyzer().inspect(_result(strings=["aGVsbG8gd29ybGQhIGFzZGZnaGprbA=="]))
    assert "string_obfuscation" in {s["name"] for s in out["signals"]}


async def test_consumes_packing_signals_base_score() -> None:
    out = await ObfuscationAnalyzer().inspect(_result(
        metadata={"packing_signals": {"signal_score": 80, "signals": ["high_entropy_section"]}},
    ))
    assert out["base_score"] == 80
    assert out["base_signals"] == ["high_entropy_section"]
    assert out["score"] >= 80


async def test_score_is_capped_at_100() -> None:
    out = await ObfuscationAnalyzer().inspect(_result(
        imports=["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"],
        strings=["UPX0", "Themida", "VmprotectBegin", "aGVsbG8gd29ybGQhIGFzZGZnaGprbA=="],
        metadata={"packing_signals": {"signal_score": 100, "signals": ["x"]}},
    ))
    assert out["score"] == 100
