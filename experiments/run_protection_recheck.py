"""Recheck protection/obfuscation recognition on the rebuilt sample suite.

After the 2026-09-25 rebuild of samples/external_protection_v05, re-run the
project's real protection classifier and obfuscation analyzer over the seven
rebuilt PE fixtures and record the results (evidence that recognition works on
the current artifacts). No target is executed.

Reproducible:  python -m experiments.run_protection_recheck
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from vulnagent.analyzers.binary.obfuscation import ObfuscationAnalyzer
from vulnagent.analyzers.binary.protection import classify_protection
from vulnagent.analyzers.binary.reverse.static import StaticBinaryReverseAnalyzer
from vulnagent.contracts import BinaryAnalysisRequest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "external_protection_v05"
OUT = ROOT / "artifacts" / "experiments" / "wp8-protection-recheck"

_TARGETS = [
    ("upx-plain", "upx_5_2_0/bin/benign_cli_plain.exe", None),
    ("upx-packed", "upx_5_2_0/bin/benign_cli_upx_5.2.0.exe", "upx/1"),
    ("nsis-level2", "nsis_3_12/bin/benign_cli_nsis_3.12_setup.exe", "nsis/2"),
    ("teaching-vm-plain", "teaching_vm/bin/teaching_vm_plain.exe", None),
    ("teaching-vm-level3", "teaching_vm/bin/teaching_vm_level3.exe", "teaching_vm/3"),
    ("string-plain", "string_obfuscation/bin/string_plain.exe", None),
    ("string-obfuscated", "string_obfuscation/bin/string_xor_base64_obfuscated.exe", None),
]


async def main() -> None:
    out = OUT
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for sample_id, rel, expected in _TARGETS:
        target = SAMPLES / rel
        if not target.is_file():
            rows.append({"sample_id": sample_id, "status": "missing",
                         "path": rel})
            continue
        result = await StaticBinaryReverseAnalyzer().analyze(
            BinaryAnalysisRequest(
                task_id=f"recheck:{sample_id}",
                target_id=sample_id,
                path=str(target),
            )
        )
        protection = classify_protection(result)
        sel = protection.get("selected") or {}
        obf = await ObfuscationAnalyzer().inspect(result)
        row = {
            "sample_id": sample_id,
            "path": rel,
            "protection_code": sel.get("code"),
            "protection_family": sel.get("family"),
            "protection_level": sel.get("level"),
            "level_name": sel.get("level_name"),
            "confidence": sel.get("confidence"),
            "evidence": sel.get("evidence") or {},
            "obfuscation_detected": getattr(obf, "detected", None) if obf else None,
            "obfuscation_summary": (obf.model_dump(mode="json")
                                    if hasattr(obf, "model_dump") and obf else None),
            "expected": expected,
            "match": (
                sel.get("code") == str(expected).split("/")[0]
                and str(sel.get("level")) == str(expected).split("/")[1]
            ) if expected else True,
        }
        rows.append(row)
        print(json.dumps({k: row[k] for k in ("sample_id", "protection_code",
                                              "protection_family",
                                              "protection_level", "confidence",
                                              "match")}, ensure_ascii=False))

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "suite": "external_protection_v05 rebuilt PE fixtures",
        "target_executed": False,
        "rows": rows,
        "all_expected_matched": all(r.get("match", False) or
                                    r.get("status") == "missing" for r in rows),
    }
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    asyncio.run(main())
