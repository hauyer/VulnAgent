"""Demo: run member-5 obfuscation and logic analyzers, then render an HTML report.

Default: analyze a synthetic, richly-featured ``BinaryAnalysisResult`` (shows
packer markers, anti-debug, authentication, cryptography and registration
clues) and write a self-contained report to ``artifacts/demo_report.html``.

Use ``--real`` to instead compile a tiny password-check C program, pack it with
UPX (downloaded into ``tools/``), lightly extract its strings (demo-only input
building, not part of the analyzer module), and report on the packed binary.

Run from the repo root:

    python scripts/demo_binary_logic.py            # synthetic + HTML report
    python scripts/demo_binary_logic.py --real     # real UPX compile/pack demo
"""

from __future__ import annotations

import asyncio
import html as _html
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnagent.analyzers.binary.logic import LogicAnalyzer
from vulnagent.analyzers.binary.obfuscation import ObfuscationAnalyzer
from vulnagent.contracts import BinaryAnalysisResult

ROOT = Path(__file__).resolve().parents[1]
UPX = ROOT / "tools" / "upx" / "upx-5.2.1-win64" / "upx.exe"
REPORT_PATH = ROOT / "artifacts" / "demo_report.html"


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


async def _analyze(result: BinaryAnalysisResult) -> tuple[dict[str, Any], dict[str, Any]]:
    obf = await ObfuscationAnalyzer().inspect(result)
    logic = await LogicAnalyzer().inspect(result)
    return obf, logic


def _print_report(obf: dict[str, Any], logic: dict[str, Any]) -> None:
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


def _render_html(result: BinaryAnalysisResult, obf: dict[str, Any], logic: dict[str, Any]) -> str:
    def esc(x: Any) -> str:
        return _html.escape(str(x))

    score = int(obf["score"])
    if score < 40:
        bar_color, verdict_color = "#2e7d32", "#1b5e20"
    elif score < 70:
        bar_color, verdict_color = "#f9a825", "#e65100"
    else:
        bar_color, verdict_color = "#c62828", "#b71c1c"

    cat_colors = {
        "authentication": "#c62828",
        "cryptography": "#1565c0",
        "registration": "#2e7d32",
    }
    cat_labels = {
        "authentication": "认证",
        "cryptography": "密码学",
        "registration": "注册授权",
    }
    src_labels = {"string": "字符串", "import": "导入", "function": "函数"}

    signal_rows = ""
    for sig in obf["signals"]:
        ev = esc("，".join(str(e) for e in sig.get("evidence", [])[:4]))
        ratio = sig.get("ratio")
        ratio_str = f" · 占比 {ratio}" if ratio is not None else ""
        signal_rows += (
            f'<tr><td><code>{esc(sig["name"])}</code></td>'
            f'<td class="num">+{esc(sig["score"])}</td>'
            f'<td>{ev}{ratio_str}</td></tr>'
        )
    if not signal_rows:
        signal_rows = '<tr><td colspan="3" class="hint">未发现明显混淆信号</td></tr>'

    loc_rows = ""
    for loc in logic["locations"]:
        color = cat_colors.get(loc["category"], "#616161")
        label = cat_labels.get(loc["category"], loc["category"])
        addr = loc["address"] or "—"
        fn = loc["function"] or ""
        src = src_labels.get(loc["source"], loc["source"])
        fn_html = f'<br><span class="hint">{esc(fn)}</span>' if fn else ""
        loc_rows += (
            f'<tr><td><span class="badge" style="background:{color}">{esc(label)}</span></td>'
            f'<td><code>{esc(loc["matched"])}</code></td>'
            f'<td>{esc(src)}</td>'
            f'<td><code>{esc(addr)}</code>{fn_html}</td>'
            f'<td class="num">{esc(loc["confidence"])}</td></tr>'
        )
    if not loc_rows:
        loc_rows = '<tr><td colspan="5" class="hint">未发现逻辑线索</td></tr>'

    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnAgent · 二进制分析报告</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: #f4f5f7; color: #1f2328; font-family: "Segoe UI", "Microsoft YaHei", -apple-system, sans-serif; }}
  .wrap {{ max-width: 960px; margin: 28px auto; padding: 0 16px 40px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .meta {{ color: #6a737d; font-size: 13px; margin-bottom: 20px; }}
  .card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px 24px; margin-bottom: 16px; }}
  .card h2 {{ font-size: 16px; margin: 0 0 14px; color: #24292f; }}
  .score {{ display: flex; align-items: center; gap: 18px; }}
  .score .num {{ font-size: 44px; font-weight: 700; color: {verdict_color}; min-width: 72px; }}
  .bar {{ flex: 1; height: 14px; background: #eceff1; border-radius: 7px; overflow: hidden; }}
  .bar > div {{ height: 100%; width: {score}%; background: {bar_color}; border-radius: 7px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #eef0f2; vertical-align: top; }}
  th {{ color: #6a737d; font-weight: 600; font-size: 12px; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ background: #f0f1f3; padding: 1px 6px; border-radius: 5px; font-size: 12px; }}
  .badge {{ color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 12px; white-space: nowrap; }}
  .hint {{ color: #9aa0a6; font-size: 12px; }}
  .num {{ font-variant-numeric: tabular-nums; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>VulnAgent · 二进制混淆 / 逻辑分析报告</h1>
  <div class="meta">target_id: {esc(result.target_id)} · 格式: {esc(result.file_format or "未知")} · 架构: {esc(result.architecture or "未知")} · 字符串: {esc(len(result.strings))} · 导入: {esc(len(result.imports))} · 生成: {gen_time}</div>

  <div class="card">
    <h2>混淆特征评分（疑似加壳 / 混淆，非结论）</h2>
    <div class="score">
      <div class="num">{score}</div>
      <div class="bar"><div></div></div>
    </div>
    <div class="hint" style="margin-top:10px">基础分 {esc(obf["base_score"])}（来自 binary-reverse 的 packing_signals）+ 本模块信号加分；分数仅表示「疑似」，不做加壳定论。</div>
    <table style="margin-top:14px">
      <tr><th>信号</th><th>加分</th><th>证据</th></tr>
      {signal_rows}
    </table>
  </div>

  <div class="card">
    <h2>业务逻辑定位（{esc(len(logic["locations"]))} 条线索）</h2>
    <table>
      <tr><th>类别</th><th>命中内容</th><th>来源</th><th>地址 / 函数</th><th>置信度</th></tr>
      {loc_rows}
    </table>
  </div>

  <div class="hint">VulnAgent · Binary Obfuscation / Logic（成员 5）· 只消费 BinaryAnalysisResult，不读取原始文件 · 仅线索，不构成漏洞结论。</div>
</div>
</body>
</html>"""


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
    if "--real" in sys.argv[1:]:
        result = _real_upx_demo()
        if result is None:
            print("[demo] 真实 UPX 路径不可用，回退到合成样本", file=sys.stderr)
            result = synthetic_result()
    else:
        result = synthetic_result()

    print(f"target_id={result.target_id}  strings={len(result.strings)}  imports={len(result.imports)}")

    obf, logic = asyncio.run(_analyze(result))
    _print_report(obf, logic)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(_render_html(result, obf, logic), encoding="utf-8")
    print(f"\nHTML 报告已生成: {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
