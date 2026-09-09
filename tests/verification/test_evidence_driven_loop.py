"""Evidence-driven Verification -> Reviewer closed loop (P7, no P3 dependency).

Simulates the post-discovery context exactly as the AgentRuntime builds it
(candidates carry ``evidence_ids``; Evidence lives in ``context.evidence``),
then runs the real ``EvidenceVerifier`` through ``VerificationAgent`` and the
independent ``ReviewerAgent``.

This proves the V0.3 evidence-first loop works without depending on P2/P3 real
implementations being merged: candidates here are built from public Contracts
the same way a real SourceAudit discovery would produce them.
"""

from vulnagent.agents import ReviewerAgent, VerificationAgent
from vulnagent.contracts import (
    AnalysisContext,
    Evidence,
    EvidenceType,
    Target,
    TargetType,
    Task,
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)
from vulnagent.verification.evidence_verifier import EvidenceVerifier

TASK_ID = "task-demo"


def make_evidence(evidence_id: str, evidence_type: EvidenceType, *, reliability: float, description: str = "discovery evidence") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        task_id=TASK_ID,
        evidence_type=evidence_type,
        source="source_audit",
        description=description,
        reliability=reliability,
        created_by="source_audit",
    )


def source_candidate(vulnerability_id: str, *, evidence_ids: list[str], location: VulnerabilityLocation) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id=vulnerability_id,
        task_id=TASK_ID,
        title="Potential command injection",
        vulnerability_type="command_injection",
        description="User input may reach an unsafe sink.",
        target_id="target-demo",
        location=location,
        source_agent="source_audit",
        source_type="source",
        confidence=0.6,
        severity="HIGH",
        evidence_ids=evidence_ids,
    )


def make_task() -> Task:
    return Task(task_id=TASK_ID, target=Target(target_id="target-demo", path="sample_app", target_type=TargetType.SOURCE))


def merge_result(context: AnalysisContext, result) -> None:
    """Mirror Pipeline.merge(..., replace_findings=True) for the VERIFICATION route."""
    context.messages.extend(result.messages)
    context.findings = result.findings
    context.evidence.extend(result.evidence)
    context.verifications.extend(result.verifications)


async def test_evidence_driven_source_loop_confirms_and_filters() -> None:
    task = make_task()
    loc_real = VulnerabilityLocation(file_path="app/parser.py", function_name="parse_cmd", line_start=40, line_end=48)
    loc_fp = VulnerabilityLocation(file_path="app/parser.py", function_name="parse_cmd", line_start=120, line_end=125)
    loc_llm = VulnerabilityLocation(file_path="app/render.py", function_name="render", line_start=5, line_end=9)

    # Real vulnerability: three independent static signals.
    evidence = [
        make_evidence("e-loc", EvidenceType.SOURCE_LOCATION, reliability=0.6),
        make_evidence("e-snip", EvidenceType.CODE_SNIPPET, reliability=0.75),
        make_evidence("e-call", EvidenceType.CALL_PATH, reliability=0.7),
    ]
    real_vuln = source_candidate("vuln-real", evidence_ids=["e-loc", "e-snip", "e-call"], location=loc_real)

    # False positive: only one weak static signal (under-proven).
    fp_evidence = [make_evidence("e-fp", EvidenceType.SOURCE_LOCATION, reliability=0.35)]
    false_positive = source_candidate("vuln-fp", evidence_ids=["e-fp"], location=loc_fp)

    # LLM-only claim: no code/runtime corroboration.
    llm_evidence = [make_evidence("e-llm", EvidenceType.MODEL_REASONING_SUMMARY, reliability=0.5)]
    llm_only = source_candidate("vuln-llm", evidence_ids=["e-llm"], location=loc_llm)

    context = AnalysisContext(
        task=task,
        findings=[real_vuln, false_positive, llm_only],
        evidence=[*evidence, *fp_evidence, *llm_evidence],
    )

    result = await VerificationAgent(EvidenceVerifier()).run(task, context)
    merge_result(context, result)

    status_by_id = {item.vulnerability_id: item.status for item in context.findings}
    assert status_by_id["vuln-real"] is VulnerabilityStatus.CONFIRMED
    assert status_by_id["vuln-fp"] is VulnerabilityStatus.UNCERTAIN
    assert status_by_id["vuln-llm"] is VulnerabilityStatus.UNCERTAIN

    # Evidence-first: every finding carries its own verdict evidence with a rationale.
    verdict_ids = {
        item.evidence_id
        for item in context.evidence
        if item.evidence_type is EvidenceType.VERIFICATION_RESULT
    }
    assert len(verdict_ids) == len(context.findings)
    for finding in context.findings:
        assert set(finding.evidence_ids).intersection(verdict_ids)
    assert any(item.data.get("rationale") for item in context.evidence if item.evidence_type is EvidenceType.VERIFICATION_RESULT)

    # Reviewer: evidence-driven results are internally consistent -> passes.
    review = await ReviewerAgent().run(task, context)
    review_payload = review.messages[0].payload
    assert review_payload["review_passed"] is True
    assert review_payload["review_notes"] == []


async def test_evidence_driven_loop_rejects_evidence_free_candidate() -> None:
    task = make_task()
    no_evidence = source_candidate(
        "vuln-empty",
        evidence_ids=[],
        location=VulnerabilityLocation(file_path="app/parser.py", function_name="parse_cmd", line_start=40, line_end=48),
    )
    context = AnalysisContext(task=task, findings=[no_evidence], evidence=[])

    result = await VerificationAgent(EvidenceVerifier()).run(task, context)
    merge_result(context, result)

    assert context.findings[0].status is VulnerabilityStatus.REJECTED
    assert context.findings[0].status is not VulnerabilityStatus.CANDIDATE

    # Rejected candidate keeps a rationale instead of being silently dropped.
    verdict = context.verifications[0]
    assert verdict.rationale
    assert verdict.metadata["verifier"] == "EvidenceVerifier"
