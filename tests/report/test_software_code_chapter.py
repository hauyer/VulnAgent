"""Software-code dossier and evidence-chain report coverage."""

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    ReportRequest,
    Target,
    TargetType,
    Task,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)
from vulnagent.report.generator import COMPLIANCE_NOTICE, StructuredReportGenerator


async def test_report_builds_software_code_dossier() -> None:
    task = Task(
        task_id="task-code-report",
        target=Target(target_id="target", path="service.c", target_type=TargetType.SOURCE),
    )
    finding = VulnerabilityCandidate(
        vulnerability_id="finding-code-report",
        task_id=task.task_id,
        title="Boundary check candidate",
        vulnerability_type="array_out_of_bounds",
        cwe_id="CWE-129",
        description="Defensive candidate.",
        target_id="target",
        location=VulnerabilityLocation(file_path="service.c", function_name="handle", line_start=10),
        source_agent="source_audit",
        confidence=0.8,
        severity="HIGH",
        metadata={
            "audit_domain": "software_code",
            "rule_id": "VA-NATIVE-BOUNDS-001",
            "cfg_path": [{"node_id": "n1", "line": 10}],
            "taint_path": ["source:api_parameter:index@4", "sink:index@10"],
        },
    )
    evidence = [
        Evidence(
            evidence_id="e-source",
            task_id=task.task_id,
            evidence_type=EvidenceType.SOURCE_LOCATION,
            source="source_audit",
            description="location",
            data={"finding_id": finding.vulnerability_id},
            reliability=0.9,
            created_by="source_audit",
        ),
        Evidence(
            evidence_id="e-model",
            task_id=task.task_id,
            evidence_type=EvidenceType.MODEL_REASONING_SUMMARY,
            source="code_audit",
            description="review",
            data={
                "finding_id": finding.vulnerability_id,
                "review_result": "uncertain",
                "remediation_summary": "检查上下界。",
                "remediation_actions": ["访问前验证下标。"],
            },
            reliability=0.55,
            created_by="code_audit",
        ),
    ]
    report = await StructuredReportGenerator().generate(
        ReportRequest(task=task, findings=[finding], evidence=evidence)
    )

    chapter = report.content["software_code_security"]
    assert report.content["compliance_notice"] == COMPLIANCE_NOTICE
    assert chapter["finding_count"] == 1
    assert chapter["risk_level_distribution"]["HIGH"] == 1
    dossier = chapter["dossiers"][0]
    assert dossier["source_location"]["line_start"] == 10
    assert dossier["control_flow_path"][-1]["line"] == 10
    assert dossier["agent_assessment"]["review_result"] == "uncertain"
    assert [item["stage"] for item in dossier["evidence_chain"]] == [
        "source_location",
        "agent_assessment",
    ]
    assert dossier["compliance_notice"] == COMPLIANCE_NOTICE
