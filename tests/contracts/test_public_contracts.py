from vulnagent.contracts import BinaryAnalysisResult, Evidence, EvidenceType, FuzzResult, ProjectInput, ReportRequest, ReportResult, SourceAnalysisResult, Target, TargetType, Task, VerificationContext, VerificationResult, VulnerabilityCandidate, VulnerabilityStatus
from vulnagent.analyzers.source.audit import MockSourceAuditor
from vulnagent.analyzers.source.parser import MockSourceParser
from vulnagent.verification.verifier import MockVerifier
from vulnagent.report.generator import MockReportGenerator

async def test_source_result_can_be_consumed_by_audit() -> None:
    parsed = await MockSourceParser().analyze(ProjectInput(task_id="t", target_id="x", project_path="sample.c"))
    assert isinstance(parsed, SourceAnalysisResult)
    findings = await MockSourceAuditor().audit(parsed)
    assert isinstance(findings[0], VulnerabilityCandidate)
    assert findings[0].status is VulnerabilityStatus.CANDIDATE

async def test_verifier_consumes_candidate_and_evidence() -> None:
    candidate = (await MockSourceAuditor().audit(SourceAnalysisResult(task_id="t", target_id="x", project_path="x")))[0]
    evidence = Evidence(evidence_id="e", task_id="t", evidence_type=EvidenceType.TOOL_RESULT, source="mock", description="x", reliability=0.5, created_by="test")
    result = await MockVerifier().verify(candidate, VerificationContext(task_id="t", evidence=[evidence]))
    assert isinstance(result, VerificationResult)
    assert result.vulnerability_id == candidate.vulnerability_id

def test_binary_and_fuzz_results_are_structured() -> None:
    assert BinaryAnalysisResult(task_id="t", target_id="x", path="a.exe").metadata == {}
    assert FuzzResult(task_id="t", target_id="x").executed is False

async def test_report_consumes_only_public_contracts() -> None:
    task = Task(task_id="t", target=Target(target_id="x", path="x", target_type=TargetType.SOURCE))
    report = await MockReportGenerator().generate(ReportRequest(task=task))
    assert isinstance(report, ReportResult)
