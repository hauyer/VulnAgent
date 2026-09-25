"""V0.6 triple-engine closed-loop demo (Native + Semgrep + Bandit -> Fusion -> Verify).

Extends the V0.5 closed loop with a third independent source engine (Bandit):

    SourceProjectParser
        -> PythonSourceAuditor (native AST + interprocedural taint)
        -> SemgrepAdapter     (external engine, local rules)
        -> BanditAdapter      (external engine, built-in plugins)
    -> CandidateFusionEngine -> EvidenceVerifier (independence-aware)
    -> evidence graph

The fused finding is expected to show three independent sources
(native-taint, semgrep, bandit) and verify to CONFIRMED.

Usage:
    python -m scripts.demo_v06_triple_engine
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from vulnagent.adapters.bandit.adapter import BanditAdapter
from vulnagent.adapters.semgrep.adapter import SemgrepAdapter
from vulnagent.analyzers.source.audit.auditor import PythonSourceAuditor
from vulnagent.analyzers.source.fusion import CandidateFusionEngine
from vulnagent.analyzers.source.parser.source_project_parser import SourceProjectParser
from vulnagent.contracts import (
    EvidenceV2,
    EvidenceType,
    ProjectInput,
    ToolExecutionRequest,
    VerificationContext,
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)
from vulnagent.evidence.graph import build_evidence_graph
from vulnagent.verification.evidence_verifier import EvidenceVerifier

TARGET_DIR = (
    Path(__file__).resolve().parent.parent
    / "benchmarks" / "source" / "py-cmd-001-vulnerable"
)
TASK_ID = "v06-triple-engine"
TARGET_ID = "py-cmd-001-vulnerable"
SESSION_ID = "v06-demo"

# Deterministic sink mapping for Bandit test ids (built-in plugin knowledge).
_BANDIT_SINKS = {
    "B602": "subprocess.run",   # subprocess_popen_with_shell_equals_true
    "B605": "subprocess.run",
    "B607": "subprocess.run",
    "B323": "os.popen",
    "B404": "subprocess",
    "B301": "pickle.loads",
    "B403": "pickle.loads",
}


def _native_evidence(candidate: VulnerabilityCandidate, run_id: str) -> EvidenceV2:
    return EvidenceV2(
        evidence_id=f"{run_id}-ev-{candidate.vulnerability_id}",
        task_id=TASK_ID,
        session_id=SESSION_ID,
        evidence_type=EvidenceType.SOURCE_LOCATION,
        producer="PythonSourceAuditor",
        analysis_run_id=run_id,
        derivation_id=f"{run_id}-{candidate.metadata.get('rule_id', 'rule')}",
        independence_group="native-taint",
        reliability=0.6,
        description=candidate.description,
        data={"rule_id": candidate.metadata.get("rule_id"), "sink": candidate.metadata.get("sink")},
    )


def _evidence_to_candidate(
    evidence: EvidenceV2,
    *,
    index: int,
    producer: str,
    title: str,
) -> VulnerabilityCandidate:
    legacy = evidence.to_legacy()
    return VulnerabilityCandidate(
        vulnerability_id=f"{producer}-{index}",
        task_id=TASK_ID,
        title=title,
        vulnerability_type="command_injection",
        cwe_id=evidence.data.get("cwe_id"),
        description=evidence.description,
        target_id=TARGET_ID,
        location=VulnerabilityLocation(
            file_path=evidence.data.get("file_path"),
            function_name=None,
            line_start=evidence.data.get("line_start"),
            line_end=evidence.data.get("line_end"),
        ),
        source_agent="source_audit",
        source_type="source",
        producer=producer,
        confidence=0.6,
        severity="WARNING",
        evidence_ids=[legacy.evidence_id],
        metadata={
            "sink": evidence.data.get("sink"),
            "source_kinds": ["dynamic_value"],
            "analysis_engine": producer,
            "rule_id": evidence.data.get("rule_id"),
        },
    )


async def main() -> None:
    print("=" * 70)
    print("VulnAgent V0.6 triple-engine closed loop")
    print(f"target: {TARGET_DIR}")
    print("=" * 70)

    parser = SourceProjectParser()
    result = await parser.analyze(
        ProjectInput(task_id=TASK_ID, target_id=TARGET_ID, project_path=str(TARGET_DIR))
    )
    print(f"[parse] languages={result.languages} files={len(result.files)}")

    # 1. Native Python AST audit (interprocedural taint).
    auditor = PythonSourceAuditor()
    native_candidates = await auditor.audit(result)
    print(f"[native] candidates={len(native_candidates)}")
    for candidate in native_candidates:
        print(
            f"  - cwe={candidate.cwe_id} sink={candidate.metadata.get('sink')} "
            f"confidence={candidate.confidence}"
        )

    # 2. Semgrep scan with local rules.
    semgrep_adapter = SemgrepAdapter()
    health = await semgrep_adapter.health()
    print(f"[semgrep] health available={health.available} version={health.version}")
    semgrep_evidence: list[EvidenceV2] = []
    if health.available:
        with tempfile.TemporaryDirectory(prefix="v06_rules_") as tmp:
            rule_file = Path(tmp) / "rules.yaml"
            rule_file.write_text(
                """rules:
  - id: vulnagent-cmd-shell
    languages: [python]
    message: shell=True command execution reachable from code
    severity: WARNING
    metadata:
      cwe: [CWE-78]
      vuln_sink: subprocess.run
    pattern: subprocess.run($X, shell=True, ...)
"""
            )
            run_id = SemgrepAdapter.new_run_id(TASK_ID)
            tool_result = await semgrep_adapter.execute(
                ToolExecutionRequest(
                    run_id=run_id,
                    task_id=TASK_ID,
                    session_id=SESSION_ID,
                    capability="source.scan.semgrep",
                    target_path=str(TARGET_DIR),
                    authorized=True,
                    timeout_seconds=300,
                    options={"config": str(rule_file)},
                )
            )
            print(f"[semgrep] success={tool_result.success} findings={len(tool_result.findings)}")
            if tool_result.success:
                semgrep_evidence = semgrep_adapter.findings_to_evidence(
                    tool_result, task_id=TASK_ID, session_id=SESSION_ID
                )
            else:
                print(f"[semgrep] FAILED metadata={tool_result.metadata} stderr={tool_result.stderr_summary!r}")
    else:
        print("[semgrep] NOT AVAILABLE; skipping semgrep leg")

    # 3. Bandit scan with built-in plugins.
    bandit_adapter = BanditAdapter()
    health = await bandit_adapter.health()
    print(f"[bandit] health available={health.available} version={health.version}")
    bandit_evidence: list[EvidenceV2] = []
    if health.available:
        run_id = BanditAdapter.new_run_id(TASK_ID)
        tool_result = await bandit_adapter.execute(
            ToolExecutionRequest(
                run_id=run_id,
                task_id=TASK_ID,
                session_id=SESSION_ID,
                capability="source.scan.bandit",
                target_path=str(TARGET_DIR),
                authorized=True,
                timeout_seconds=120,
            )
        )
        print(f"[bandit] success={tool_result.success} findings={len(tool_result.findings)}")
        for finding in tool_result.findings:
            print(f"  - {finding.rule_id} {finding.file_path}:{finding.line_start} {finding.severity}")
        if tool_result.success:
            bandit_evidence = bandit_adapter.findings_to_evidence(
                tool_result, task_id=TASK_ID, session_id=SESSION_ID
            )
        else:
            print(f"[bandit] FAILED metadata={tool_result.metadata}")
    else:
        print("[bandit] NOT AVAILABLE; skipping bandit leg")

    # 4. Provenance evidence + candidate assembly.
    native_evidence = [_native_evidence(c, f"native-run-{TASK_ID}") for c in native_candidates]
    all_evidence = native_evidence + semgrep_evidence + bandit_evidence
    for evidence in all_evidence:
        legacy = evidence.to_legacy()
        for candidate in native_candidates:
            if candidate.vulnerability_id in evidence.evidence_id:
                if legacy.evidence_id not in candidate.evidence_ids:
                    candidate.evidence_ids.append(legacy.evidence_id)

    external_candidates: list[VulnerabilityCandidate] = []
    for index, evidence in enumerate(semgrep_evidence):
        external_candidates.append(
            _evidence_to_candidate(evidence, index=index, producer="semgrep", title="Potential command injection (semgrep)")
        )
    for index, evidence in enumerate(bandit_evidence):
        sink = _BANDIT_SINKS.get(str(evidence.data.get("rule_id") or ""))
        if sink:
            evidence.data["sink"] = sink
        external_candidates.append(
            _evidence_to_candidate(evidence, index=index, producer="bandit", title="Potential command injection (bandit)")
        )
    all_candidates = native_candidates + external_candidates

    # 5. Fuse with independence groups.
    engine = CandidateFusionEngine()
    groups: dict[str, str] = {}
    for candidate in all_candidates:
        for evidence_id in candidate.evidence_ids:
            for item in all_evidence:
                if item.evidence_id == evidence_id and item.independence_group:
                    groups[candidate.vulnerability_id] = item.independence_group
    fused = engine.fuse(all_candidates, groups, base_path=TARGET_DIR)
    print(f"[fusion] fused findings={len(fused)}")
    for item in fused:
        print(
            f"  - cwe={item.cwe_id} members={item.source_candidates} "
            f"independence={item.supporting_independence_groups} confidence={item.fused_confidence}"
        )

    # 6. Independence-aware verification on the fused finding.
    if fused:
        primary = fused[0]
        candidate = next(c for c in all_candidates if c.vulnerability_id == primary.source_candidates[0])
        candidate.evidence_ids = list(primary.evidence_ids)
        verifier = EvidenceVerifier()
        verdict = await verifier.verify(
            candidate,
            VerificationContext(task_id=TASK_ID, evidence=[e.to_legacy() for e in all_evidence]),
        )
        print(
            f"[verify] status={verdict.status.value} confidence={verdict.confidence} "
            f"independent_sources={verdict.metadata.get('independent_sources')} "
            f"stage={verdict.metadata.get('stage')}"
        )

    # 7. Evidence graph.
    graph = build_evidence_graph(all_candidates, [e.to_legacy() for e in all_evidence], [])
    print(f"[graph] nodes={len(graph['nodes'])} edges={len(graph['edges'])}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
