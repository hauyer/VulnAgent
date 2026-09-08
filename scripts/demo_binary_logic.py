"""Demo: run member-5 obfuscation and logic analyzers.

Uses a synthetic ``BinaryAnalysisResult`` by default.  If a C compiler and the
UPX binary (downloaded into ``tools/``) are both available, it instead compiles
a tiny password-check program, packs it with UPX, lightly extracts its strings
(demo-only input building, not part of the analyzer module), and feeds that
result to the analyzers.

Run from the repo root:

    python scripts/demo_binary_logic.py
"""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from vulnagent.analyzers.binary.logic import LogicAnalyzer
from vulnagent.analyzers.binary.obfuscation import ObfuscationAnalyzer
from vulnagent.contracts import BinaryAnalysisResult

ROOT = Path(__file__).resolve().parents[1]
UPX = ROOT / "tools" / "upx" / "upx-5.2.1-win64" / "upx.exe"


def synthetic_result() -> BinaryAnalysisResult:
    """A realistic packed binary with auth / license logic."""
    return BinaryAnalysisResult(
        task_id="demo/task",
        target_id="demo:packed-crackme",
        path="packed_crackme.exe",
        file_format="PE",
        architecture="x86-64",
        strings=[
            "UPX!", "UPX0", "UPX1",
            "Please enter the password:",
            "Incorrect password, access denied",
            "License key is invalid or expired",
            "BCryptVerifySignature",
            "VmprotectBegin",
            "aGVsbG8gd29ybGQhIGFzZGZnaGprbA==",
        ],
        imports=[
            "BCryptVerifySignature",
            "IsDebuggerPresent",
            "NtQueryInformationProcess",
            "kernel32.dll!GetTickCount",
        ],
        functions=[
            {"name": "verify_password", "address": 0x401000},
            {"name": "check_license", "address": 0x401200},
        ],
        metadata={
            "packing_signals": {
                "signal_score": 80,
                "signals": ["high_entropy_section", "packer_section_name"],
            },
        },
    )


async def run(result: BinaryAnalysisResult) -> None:
    obf = await ObfuscationAnalyzer().inspect(result)
    logic = await LogicAnalyzer().inspect(result)

    print("\n=== Obfuscation signals ===")
    print(f"score={obf['score']}  base_score={obf['base_score']}")
    for sig in obf["signals"]:
        print(f"  - {sig['name']} (+{sig['score']}) evidence={sig.get('evidence', [])[:3]}")

    print("\n=== Logic locations ===")
    for loc in logic["locations"]:
        addr = loc["address"] or "-"
        print(f"  [{loc['category']}] {loc['matched']!r} src={loc['source']} addr={addr} conf={loc['confidence']}")

    print("\n=== Summary ===")
    print(logic["summary"])


def _real_upx_demo() -> BinaryAnalysisResult | None:
    """Compile + pack a tiny crackme and return a result built from its strings."""
    if shutil.which("gcc") is None or not UPX.exists():
        return None
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "crackme.c"
            src.write_text(
                "#include <stdio.h>\n#include <string.h>\n"
                "int main(int c, char** v){"
                "if(c<2){puts(\"Please enter the password:\");return 1;}"
                "if(strcmp(v[1],\"s3cr3t\")==0){puts(\"Access granted\");}"
                "else{puts(\"Incorrect password, access denied\");}return 0;}\n",
                encoding="utf-8",
            )
            exe = tmp_path / "crackme.exe"
            subprocess.run(["gcc", str(src), "-o", str(exe)], check=True)
            packed = tmp_path / "crackme_packed.exe"
            subprocess.run([str(UPX), "-9", "-q", "-o", str(packed), str(exe)], check=True)
            return BinaryAnalysisResult(
                task_id="demo/task",
                target_id="demo:real-upx",
                path=str(packed),
                file_format="PE",
                strings=_ascii_strings(packed.read_bytes()),
                imports=[],
                metadata={"packing_signals": {"signal_score": 80, "signals": ["packer_section_name"]}},
            )
    except Exception as exc:  # noqa: BLE001 - demo falls back to synthetic
        print(f"[demo] real UPX path skipped: {exc}", file=sys.stderr)
        return None


def _ascii_strings(data: bytes, min_len: int = 5) -> list[str]:
    runs = re.findall(rb"[ -~]{%d,}" % min_len, data)
    return [run.decode("ascii", "replace") for run in runs]


def main() -> int:
    result = _real_upx_demo() or synthetic_result()
    print(f"target_id={result.target_id}  strings={len(result.strings)}  imports={len(result.imports)}")
    asyncio.run(run(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
