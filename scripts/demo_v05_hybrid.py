"""V0.5 hybrid analysis closed-loop demo (Native + Semgrep -> Fusion -> Verify).

Runs the blueprint's minimal closed loop (docs appendix C) on a local
benchmark target:

    SourceProjectParser -> PythonSourceAuditor (native)
                        -> SemgrepAdapter (external engine)
    -> CandidateFusionEngine -> EvidenceVerifier (independence-aware)
    -> evidence graph

Usage:
    python -m scripts.demo_v05_hybrid
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

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

TARGET_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "source" / "py-cmd-001-vulnerable"
TASK_ID = "v05-closed-loop"
TARGET_ID = "py-cmd-001-vulnerable"
SESSION_ID = "v05-demo"


def _native_evidence(candidate: VulnerabilityCandidate, run_id: str) -> EvidenceV2:
    """Wrap one native candidate as provenance-carrying evidence (demo)."""
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


async def main() -> None:
    print("=" * 70)
    print("VulnAgent V0.5 hybrid closed loop")
    print(f"target: {TARGET_DIR}")
    print("=" * 70)

    # 1. Parse the project once; both engines consume the same intake.
    parser = SourceProjectParser()
    result = await parser.analyze(
        ProjectInput(task_id=TASK_ID, target_id=TARGET_ID, project_path=str(TARGET_DIR))
    )
    print(f"[parse] languages={result.languages} files={len(result.files)}")

    # 2. Native Python AST audit.
    auditor = PythonSourceAuditor()
    native_candidates = await auditor.audit(result)
    print(f"[native] candidates={len(native_candidates)}")
    for candidate in native_candidates:
        print(
            f"  - {candidate.vulnerability_id} cwe={candidate.cwe_id} "
            f"sink={candidate.metadata.get('sink')} confidence={candidate.confidence}"
        )

    # 3. Semgrep scan (local rules => deterministic, no registry download).
    adapter = SemgrepAdapter()
    health = await adapter.health()
    print(f"[semgrep] health available={health.available} version={health.version}")
    if not health.available:
        print("[semgrep] NOT AVAILABLE; skipping semgrep leg (closed loop degrades gracefully)")
        semgrep_evidence: list[EvidenceV2] = []
    else:
        with tempfile.TemporaryDirectory(prefix="v05_rules_") as tmp:
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
            tool_result = await adapter.execute(
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
        if not tool_result.success:
            print(f"[semgrep] metadata={tool_result.metadata}")
            print(f"[semgrep] stderr={tool_result.stderr_summary!r}")
            print(f"[semgrep] stdout_head={tool_result.stdout_summary!r}")
        for finding in tool_result.findings:
            print(f"  - {finding.rule_id} {finding.file_path}:{finding.line_start} {finding.severity}")
        semgrep_evidence = (
            adapter.findings_to_evidence(tool_result, task_id=TASK_ID, session_id=SESSION_ID)
            if tool_result.success
            else []
        )

    # 4. Attach provenance evidence to native candidates and fuse everything.
    native_evidence = [
        _native_evidence(c, f"native-run-{TASK_ID}") for c in native_candidates
    ]
    all_evidence = native_evidence + semgrep_evidence
    for evidence in all_evidence:
        evidence_legacy = evidence.to_legacy()
        for candidate in native_candidates:
            if candidate.vulnerability_id in evidence.evidence_id:
                if evidence_legacy.evidence_id not in candidate.evidence_ids:
                    candidate.evidence_ids.append(evidence_legacy.evidence_id)
    # Semgrep findings become candidates so the fusion layer can merge them.
    semgrep_candidates: list[VulnerabilityCandidate] = []
    for index, evidence in enumerate(semgrep_evidence):
        legacy = evidence.to_legacy()
        semgrep_candidates.append(
            VulnerabilityCandidate(
                vulnerability_id=f"semgrep-{index}",
                task_id=TASK_ID,
                title="Potential command injection (semgrep)",
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
                producer="semgrep",
                confidence=0.6,
                severity="WARNING",
                evidence_ids=[legacy.evidence_id],
                metadata={
                    "sink": evidence.data.get("sink"),
                    "source_kinds": ["dynamic_value"],
                    "analysis_engine": "semgrep",
                    "rule_id": evidence.data.get("rule_id"),
                },
            )
        )
    all_candidates = native_candidates + semgrep_candidates

    engine = CandidateFusionEngine()
    groups = {}
    for candidate in all_candidates:
        for evidence_id in candidate.evidence_ids:
            for item in all_evidence:
                if item.evidence_id == evidence_id and item.independence_group:
                    groups[candidate.vulnerability_id] = item.independence_group
    fused = engine.fuse(all_candidates, groups, base_path=TARGET_DIR)
    print(f"[fusion] fused findings={len(fused)}")
    for item in fused:
        print(
            f"  - {item.candidate_id} cwe={item.cwe_id} members={item.source_candidates} "
            f"independence={item.supporting_independence_groups} confidence={item.fused_confidence}"
        )

    # 5. Independence-aware verification on the fused finding.
    if fused:
        primary = fused[0]
        candidate = next(c for c in all_candidates if c.vulnerability_id == primary.source_candidates[0])
        # Verify against the FULL fused evidence set (both engines), not just
        # the primary candidate's own evidence.
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

    # 6. Evidence graph.
    graph = build_evidence_graph(
        all_candidates,
        [e.to_legacy() for e in all_evidence],
        [],
    )
    print(f"[graph] nodes={len(graph['nodes'])} edges={len(graph['edges'])}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
