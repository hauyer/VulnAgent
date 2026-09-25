"""V0.6 evaluation experiment: run the native auditor over benchmarks/source.

Ground truth comes only from sample directory names (``*-vulnerable`` vs
``*-clean``); it never feeds an analyzer.  Per sample we count candidates
and classify sample-level TP / FP, then print a comparison table that
highlights the V0.6 interprocedural fixtures (005/006/007).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vulnagent.analyzers.source.audit import PythonSourceAuditor
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.contracts import ProjectInput

BENCH_SOURCE = ROOT / "benchmarks" / "source"


def sample_truth(directory: Path) -> bool:
    """True when the directory name marks a vulnerable sample."""
    return "vulnerable" in directory.name


async def audit_sample(directory: Path) -> list:
    parsed = await SourceProjectParser().analyze(
        ProjectInput(
            task_id=f"eval-{directory.name}",
            target_id=directory.name,
            project_path=str(directory),
        )
    )
    return await PythonSourceAuditor().audit(parsed)


async def main() -> None:
    samples = sorted(
        item for item in BENCH_SOURCE.iterdir()
        if item.is_dir() and item.name.startswith("py-")
    )
    rows = []
    for sample in samples:
        findings = await audit_sample(sample)
        expected = sample_truth(sample)
        by_cwe: dict[str, int] = {}
        for finding in findings:
            by_cwe[finding.cwe_id] = by_cwe.get(finding.cwe_id, 0) + 1
        hit = bool(findings)
        verdict = "TP" if (expected and hit) else ("FP" if (not expected and hit) else "TN" if not expected else "FN")
        rows.append(
            (sample.name, "vuln" if expected else "clean", hit, by_cwe or {}, verdict)
        )

    tp = sum(1 for row in rows if row[4] == "TP")
    fp = sum(1 for row in rows if row[4] == "FP")
    fn = sum(1 for row in rows if row[4] == "FN")
    tn = sum(1 for row in rows if row[4] == "TN")

    print(f"{'sample':<40} {'truth':<6} {'hit':<5} {'cwes':<32} verdict")
    print("-" * 100)
    for name, truth, hit, cwes, verdict in rows:
        mark = "  <-- V0.6 interproc" if any(k in name for k in ("005", "006", "007")) else ""
        cwe_text = ",".join(f"{k}x{v}" for k, v in sorted(cwes.items())) or "-"
        print(f"{name:<40} {truth:<6} {str(hit):<5} {cwe_text:<32} {verdict}{mark}")

    print("-" * 100)
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}  samples={len(rows)}")
    print(f"precision={tp/(tp+fp) if tp+fp else 'n/a'}  recall={tp/(tp+fn) if tp+fn else 'n/a'}")
    return 0 if fp == 0 and fn == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
