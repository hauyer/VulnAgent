"""Coverage for the eight-family, multi-signal protection matrix."""

import pytest

from vulnagent.analyzers.binary.protection import classify_protection
from vulnagent.contracts import BinaryAnalysisResult


@pytest.mark.parametrize(
    ("section", "marker", "expected"),
    [
        ("UPX0", "", "upx"),
        (".aspack", "", "aspack"),
        ("FSG!", "", "fsg"),
        ("PEC1", "", "pecompact"),
        (".upack", "", "upack"),
        (".ndata", "Nullsoft", "nsis"),
        (".vmp1", "VMProtectBegin", "vmprotect_demo"),
        (".vcode", "VulnAgent Teaching VM", "teaching_vm"),
    ],
)
def test_classifies_supported_family(section: str, marker: str, expected: str) -> None:
    result = BinaryAnalysisResult(
        task_id="task",
        target_id="target",
        path="teaching.exe",
        file_format="PE",
        strings=[marker] if marker else [],
        imports=["KERNEL32.dll!ExitProcess"],
        metadata={
            "entry_point": 0x401000,
            "sections": [{
                "name": section,
                "address": 0x401000,
                "virtual_size": 0x1000,
                "entropy": 7.8,
            }],
            "declared_protection": "untrusted manifest label",
        },
    )
    assessment = classify_protection(result)
    assert assessment["selected"]["code"] == expected
    assert assessment["declaration_used_for_scoring"] is False
    assert assessment["strategy"]


def test_unknown_high_entropy_protection_is_not_named_from_declaration() -> None:
    result = BinaryAnalysisResult(
        task_id="task",
        target_id="target",
        path="teaching.exe",
        file_format="PE",
        imports=[],
        metadata={
            "declared_protection": "UPX",
            "entry_point": 0x401000,
            "sections": [{
                "name": ".mystery",
                "address": 0x401000,
                "virtual_size": 0x1000,
                "entropy": 7.9,
            }],
        },
    )
    assert classify_protection(result)["selected"]["code"] == "unknown_protector"
