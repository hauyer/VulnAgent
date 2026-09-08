"""Unit tests for the business-logic locator."""

from vulnagent.analyzers.binary.logic import LogicAnalyzer
from vulnagent.contracts import BinaryAnalysisResult


def _result(**kwargs) -> BinaryAnalysisResult:
    defaults = {"task_id": "t", "target_id": "x", "path": "a.exe"}
    defaults.update(kwargs)
    return BinaryAnalysisResult(**defaults)


async def test_empty_result_has_no_locations() -> None:
    out = await LogicAnalyzer().inspect(_result())
    assert out["locations"] == []


async def test_string_auth_hint() -> None:
    out = await LogicAnalyzer().inspect(_result(strings=["Incorrect password, access denied"]))
    assert any(loc["category"] == "authentication" for loc in out["locations"])


async def test_import_crypto_hint() -> None:
    out = await LogicAnalyzer().inspect(_result(imports=["CryptEncrypt"]))
    loc = out["locations"][0]
    assert loc["category"] == "cryptography"
    assert loc["source"] == "import"
    assert loc["confidence"] == 0.75


async def test_function_name_pins_address() -> None:
    out = await LogicAnalyzer().inspect(_result(functions=[{"name": "verify_password", "address": 0x401000}]))
    loc = next(l for l in out["locations"] if l["source"] == "function")
    assert loc["address"] == hex(0x401000)
    assert loc["confidence"] == 0.85


async def test_matching_is_case_insensitive() -> None:
    out = await LogicAnalyzer().inspect(_result(strings=["PASSWORD"]))
    assert any(loc["category"] == "authentication" for loc in out["locations"])


async def test_pseudocode_pins_address() -> None:
    out = await LogicAnalyzer().inspect(_result(
        strings=["license_key"],
        metadata={"reverse_tool": {"pseudocode": {"0x401200": "int check(){ validate_license_key(); }"}}},
    ))
    loc = next(l for l in out["locations"] if l["matched"].lower() == "license_key")
    assert loc["address"] == "0x401200"
