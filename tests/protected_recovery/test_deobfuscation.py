"""Deterministic recovery tests for four OLLVM-style pattern families."""

from vulnagent.analyzers.binary.deobfuscation import StaticDeobfuscationEngine
from vulnagent.contracts import BinaryAnalysisResult


async def test_recovers_cfg_substitutions_and_strings() -> None:
    result = BinaryAnalysisResult(
        task_id="task",
        target_id="target",
        path="owned.exe",
        strings=["YWRtaW4tcGFuZWw="],
        cfg={
            "0x10": ["0x20"],
            "0x20": ["0x30", "0x40", "0x50"],
            "0x30": ["0x20"],
            "0x40": ["0x20"],
            "0x50": [],
            "0xdead": [],
        },
        metadata={
            "entry_point": 0x10,
            "reverse_tool": {
                "pseudocode": {
                    "0x30": "value = (left + (~right + 1)); if (((x * (x - 1)) & 1) == 0) goto ok;",
                }
            },
            "string_decoders": [{"algorithm": "xor", "key": 42, "cipher_hex": "594f49584f5e"}],
        },
    )
    recovery = await StaticDeobfuscationEngine().restore(result)
    assert set(recovery["detected_types"]) == {
        "control_flow_flattening",
        "bogus_control_flow",
        "instruction_substitution",
        "string_encryption",
    }
    assert recovery["control_flow"]["dispatcher_candidates"] == ["0x20"]
    assert recovery["control_flow"]["bogus_nodes_removed"] == ["0xdead"]
    function = recovery["instruction_recovery"]["functions"][0]
    assert "left - right" in function["after"]
    plaintexts = {item["plaintext"] for item in recovery["string_recovery"]["items"]}
    assert {"admin-panel", "secret"}.issubset(plaintexts)
    assert recovery["readability"]["after"] >= recovery["readability"]["before"]
