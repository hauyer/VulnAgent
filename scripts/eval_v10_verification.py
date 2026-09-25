"""V1.0 acceptance 27.7: Verification 2.0 comparison experiment.

Measures the False Confirmed Rate with Verification switched off (any
candidate is immediately "confirmed") versus the independence-aware
Verification 2.0 pipeline (native + semgrep + bandit -> fusion -> verifier;
CONFIRMED requires >= 2 independent source groups with probative static
evidence).

Ground truth comes only from sample directory names; it never feeds an
analyzer.  On the ``*-clean`` samples a naive pipeline confirms false
positives, while Verification 2.0 must reject/uncertain them, proving the
False Confirmed Rate drop the V1.0 acceptance requires.

Usage:
    python -m scripts.eval_v10_verification
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from vulnagent.adapters.bandit.adapter import BanditAdapter
from vulnagent.adapters.semgrep.adapter import SemgrepAdapter
from vulnagent.analyzers.source.audit import PythonSourceAuditor
from vulnagent.analyzers.source.fusion import CandidateFusionEngine
from vulnagent.analyzers.source.parser import SourceProjectParser
from vulnagent.contracts import (
    ProjectInput,
    ToolExecutionRequest,
    VerificationContext,
    VulnerabilityStatus,
)
from vulnagent.verification.evidence_verifier import EvidenceVerifier

BENCH_SOURCE = ROOT / "benchmarks" / "source"
SESSION_ID = "eval-v10"

_RULES_YAML = """rules:
  - id: vulnagent-cmd-shell
    languages: [python]
    message: shell=True command execution reachable from code
    severity: WARNING
    metadata:
      cwe: [CWE-78]
      vuln_sink: subprocess.run
    pattern: subprocess.run($X, shell=True, ...)
  - id: vulnagent-deser-pickle
    languages: [python]
    message: unsafe deserialization
    severity: WARNING
    metadata:
      cwe: [CWE-502]
      vuln_sink: pickle.loads
    pattern: pickle.loads($X)
  - id: vulnagent-eval
    languages: [python]
    message: dynamic code execution
    severity: WARNING
    metadata:
      cwe: [CWE-95]
      vuln_sink: eval
    pattern: eval($X)
  - id: vulnagent-path-traversal
    languages: [python]
    message: path manipulation
    severity: WARNING
    metadata:
      cwe: [CWE-22]
      vuln_sink: open
    pattern: open($X, ...)
  - id: vulnagent-sql
    languages: [python]
    message: sql string formatting
    severity: WARNING
    metadata:
      cwe: [CWE-89]
      vuln_sink: execute
    pattern: execute($X % $Y, ...)
  - id: vulnagent-yaml-load
    languages: [python]
    message: unsafe yaml load
    severity: WARNING
    metadata:
      cwe: [CWE-502]
      vuln_sink: yaml.load
    pattern: yaml.load($X, ...)
"""


def sample_truth(directory: Path) -> bool:
    return "vulnerable" in directory.name


def _finding_to_candidate(finding, *, producer: str, cwe: str, sink: str, target_id: str, task_id: str):
    from vulnagent.contracts import VulnerabilityCandidate, VulnerabilityLocation

    return VulnerabilityCandidate(
        vulnerability_id=f"{producer}-{task_id}-{finding.get('rule_id', producer)}",
        task_id=task_id,
        title=f"{producer} finding",
        vulnerability_type="finding",
        cwe_id=cwe,
        description=str(finding.get("message", "")),
        target_id=target_id,
        location=VulnerabilityLocation(
            file_path=str(finding.get("file_path", "")),
            line_start=finding.get("line_start"),
            line_end=finding.get("line_end"),
        ),
        source_agent="source_audit",
        source_type="source",
        producer=producer,
        confidence=0.6,
        severity="WARNING",
        evidence_ids=[],
        metadata={"sink": sink, "source_kinds": ["dynamic_value"], "analysis_engine": producer},
    )


async def run_sample(sample: Path, rule_file: Path) -> tuple[Path, bool, int, int, list[str]]:
    """Return (sample, truth, naive_confirmed_count, verified_confirmed_count, reasons)."""
    task_id = f"eval10-{sample.name}"
    parsed = await SourceProjectParser().analyze(
        ProjectInput(task_id=task_id, target_id=sample.name, project_path=str(sample))
    )
    native = await PythonSourceAuditor().audit(parsed)
    candidates = list(native)

    from vulnagent.contracts import EvidenceV2, EvidenceType

    native_evidence = [
        EvidenceV2(
            evidence_id=f"native-{candidate.vulnerability_id}",
            task_id=task_id,
            session_id=SESSION_ID,
            evidence_type=EvidenceType.SOURCE_LOCATION,
            producer="PythonSourceAuditor",
            analysis_run_id=f"native-run-{task_id}",
            derivation_id=f"native-{candidate.metadata.get('rule_id', 'rule')}",
            independence_group="native-taint",
            reliability=0.6,
            description=candidate.description,
            data={
                "rule_id": candidate.metadata.get("rule_id"),
                "sink": candidate.metadata.get("sink"),
                "file_path": candidate.location.file_path,
                "line_start": candidate.location.line_start,
                "line_end": candidate.location.line_end,
                "cwe_id": candidate.cwe_id,
            },
        )
        for candidate in candidates
    ]
    evidence = [item.to_legacy() for item in native_evidence]
    for candidate, item in zip(candidates, native_evidence):
        candidate.evidence_ids.append(item.evidence_id)

    semgrep = SemgrepAdapter()
    bandit = BanditAdapter()
    external = []
    if await semgrep.health() is not None and (await semgrep.health()).available:
        run_id = SemgrepAdapter.new_run_id(task_id)
        tool_result = await semgrep.execute(
            ToolExecutionRequest(
                run_id=run_id, task_id=task_id, session_id=SESSION_ID,
                capability="source.scan.semgrep", target_path=str(sample),
                authorized=True, timeout_seconds=120, options={"config": str(rule_file)},
            )
        )
        if tool_result.success:
            evidence.extend(e.to_legacy() for e in semgrep.findings_to_evidence(tool_result, task_id=task_id, session_id=SESSION_ID))
    bandit_health = await bandit.health()
    if bandit_health.available:
        run_id = BanditAdapter.new_run_id(task_id)
        tool_result = await bandit.execute(
            ToolExecutionRequest(
                run_id=run_id, task_id=task_id, session_id=SESSION_ID,
                capability="source.scan.bandit", target_path=str(sample),
                authorized=True, timeout_seconds=60,
            )
        )
        if tool_result.success:
            evidence.extend(e.to_legacy() for e in bandit.findings_to_evidence(tool_result, task_id=task_id, session_id=SESSION_ID))

    # Map external evidence to candidates by line.
    for item in evidence:
        line = item.data.get("line_start")
        sink = item.data.get("sink") or item.data.get("rule_id")
        producer = item.data.get("provenance", {}).get("producer") or "external"
        candidate = _finding_to_candidate(
            {"rule_id": item.data.get("rule_id", "ext"), "message": item.description,
             "file_path": item.data.get("file_path"), "line_start": line, "line_end": line},
            producer=producer, cwe=item.data.get("cwe_id") or "CWE-78",
            sink=sink, target_id=sample.name, task_id=task_id,
        )
        candidate.evidence_ids.append(item.evidence_id)
        external.append(candidate)
    all_candidates = candidates + external

    # Fusion (independent groups only).
    fused = CandidateFusionEngine().fuse(all_candidates, {
        c.vulnerability_id: next(
            (e.data.get("provenance", {}).get("independence_group") for e in evidence if e.evidence_id in c.evidence_ids), None
        ) or "native-taint"
        for c in all_candidates
    }, base_path=sample)

    naive_confirmed = len(fused)  # Verification off: every fused finding is "confirmed".

    verified_confirmed = 0
    if fused:
        verifier = EvidenceVerifier()
        for item in fused:
            candidate = next(c for c in all_candidates if c.vulnerability_id == item.source_candidates[0])
            candidate.evidence_ids = list(item.evidence_ids)
            verdict = await verifier.verify(
                candidate, VerificationContext(task_id=task_id, evidence=evidence)
            )
            if verdict.status == VulnerabilityStatus.CONFIRMED:
                verified_confirmed += 1
    return sample, sample_truth(sample), naive_confirmed, verified_confirmed, []


async def main() -> None:
    samples = sorted(
        item for item in BENCH_SOURCE.iterdir()
        if item.is_dir() and item.name.startswith("py-")
    )
    with tempfile.TemporaryDirectory(prefix="eval10_") as tmp:
        rule_file = Path(tmp) / "rules.yaml"
        rule_file.write_text(_RULES_YAML)
        rows = []
        for sample in samples:
            _, truth, naive, verified, _ = await run_sample(sample, rule_file)
            rows.append((sample.name, truth, naive, verified))

    clean_total = sum(1 for _, truth, _, _ in rows if not truth)
    naive_clean_confirmed = sum(1 for _, truth, naive, _ in rows if not truth and naive > 0)
    verified_clean_confirmed = sum(1 for _, truth, _, verified in rows if not truth and verified > 0)

    print(f"{'sample':<40} {'truth':<6} {'naive':<6} {'v2.conf':<8}")
    print("-" * 66)
    for name, truth, naive, verified in rows:
        print(f"{name:<40} {'vuln' if truth else 'clean':<6} {naive:<6} {verified:<8}")

    print("-" * 66)
    naive_fcr = naive_clean_confirmed / clean_total if clean_total else 0.0
    verified_fcr = verified_clean_confirmed / clean_total if clean_total else 0.0
    print(f"clean samples={clean_total}")
    print(f"False Confirmed Rate  [verification OFF ] = {naive_fcr:.2%}  ({naive_clean_confirmed}/{clean_total})")
    print(f"False Confirmed Rate  [verification 2.0 ] = {verified_fcr:.2%}  ({verified_clean_confirmed}/{clean_total})")
    print(f"FCR reduction = {(naive_fcr - verified_fcr) / naive_fcr if naive_fcr else 'n/a'}")
    return 0 if verified_fcr < naive_fcr else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
