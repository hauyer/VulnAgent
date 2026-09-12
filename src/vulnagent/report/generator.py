"""Structured, evidence-first report generation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from vulnagent.contracts import AnalysisContext, Evidence, EvidenceType, ReportRequest, ReportResult, VerificationResult, VulnerabilityCandidate, VulnerabilityStatus
from vulnagent.evidence.graph import build_evidence_graph
from vulnagent.report.remediation import DISCLAIMER, guidance_for, normalize_cwe, remediation_priority
from vulnagent.report.severity import SEVERITY_ORDER, severity_cn, severity_label, severity_label_from_rank, severity_rank

TOP_RISKS_LIMIT = 5
COMPLIANCE_NOTICE = "仅用于安全审计与防御研究，仅限教学实验使用"
_FINAL_STATUSES = ("confirmed", "verifying")

# Deterministic Chinese note per effective finding status (VerificationResult wins).
_REASONING_NOTES = {
    "confirmed": "该发现已由独立验证确认。",
    "rejected": "该发现已被独立验证排除（判定为误报）。",
    "uncertain": "该发现验证结果不确定，仍需人工复核。",
    "verifying": "该发现正在验证流程中，尚未给出结论。",
    "candidate": "该发现尚未经过独立验证，不能作为确认结论。",
}
_UNVERIFIED_NOTE = "该发现尚未经过独立验证，不能作为确认结论。"


def generate_report(context: AnalysisContext) -> dict[str, Any]:
    """Compatibility helper for callers that hold an ``AnalysisContext``."""
    return _build_content(ReportRequest(
        task=context.task,
        findings=context.findings,
        evidence=context.evidence,
        verifications=context.verifications,
    ))


class StructuredReportGenerator:
    """Generate a structured report without reading capability internals.

    The class name remains for composition-root compatibility during V0.2; its
    output is deliberately driven by the public, structured request rather than
    a synthesized LLM narrative.
    """

    async def generate(self, request: ReportRequest) -> ReportResult:
        content = _build_content(request)
        input_mode = (
            "mock"
            if request.findings and all(item.metadata.get("mock") for item in request.findings)
            else "real"
        )
        return ReportResult(
            task_id=request.task.task_id,
            content=content,
            artifact_uri=f"memory://reports/{request.task.task_id}",
            metadata={
                "generator": "structured",
                "version": "v0.4",
                "input_mode": input_mode,
            },
        )


# Backward-compatible alias: V0.1-era callers and in-repo tests import the
# previous name. The class was renamed as part of the V0.2 structured-report
# work; both names must keep resolving to the same generator.
MockReportGenerator = StructuredReportGenerator


def _build_content(request: ReportRequest) -> dict[str, Any]:
    evidence_by_id = {item.evidence_id: item for item in request.evidence}
    verifications_by_finding = {item.vulnerability_id: item for item in request.verifications}
    missing_evidence_ids: set[str] = set()
    findings: list[dict[str, Any]] = []

    severity_by_finding: dict[str, int] = {}
    effective_status_by_finding: dict[str, str] = {}

    for finding in request.findings:
        verification = verifications_by_finding.get(finding.vulnerability_id)
        related_ids = set(finding.evidence_ids)
        if verification is not None:
            related_ids.update(verification.evidence_ids)
        missing_evidence_ids.update(evidence_id for evidence_id in related_ids if evidence_id not in evidence_by_id)

        effective_status = _effective_status(finding, verification)
        rank = severity_rank(finding.severity)
        severity_by_finding[finding.vulnerability_id] = rank
        effective_status_by_finding[finding.vulnerability_id] = effective_status

        findings.append({
            "finding": finding.model_dump(mode="json"),
            "verification": verification.model_dump(mode="json") if verification else None,
            "evidence": [evidence_by_id[evidence_id].model_dump(mode="json") for evidence_id in sorted(related_ids) if evidence_id in evidence_by_id],
            "severity": _severity_block(finding.severity),
            "reasoning": _reasoning_block(finding, verification, effective_status, evidence_by_id),
            "remediation": _remediation_block(finding, effective_status, rank),
        })

    statuses = {status.value: 0 for status in VulnerabilityStatus}

    for finding in request.findings:
        verification = verifications_by_finding.get(
            finding.vulnerability_id
        )
        effective_status = _effective_status(
            finding,
            verification
        )
        statuses[effective_status] += 1

    return {
        "compliance_notice": COMPLIANCE_NOTICE,
        "task": request.task.model_dump(mode="json"),
        "summary": {
            "finding_count": len(request.findings),
            "evidence_count": len(request.evidence),
            "verification_count": len(request.verifications),
            "findings_by_status": statuses,
            "findings_by_severity": _build_severity_distribution(request.findings),
            "severity_ordered_finding_ids": _build_severity_ordered_ids(request.findings),
        },
        "findings": findings,
        "cwe_classification": _build_cwe_classification(request.findings),
        "evidence_timeline": _build_evidence_timeline(request.evidence, request.findings, request.verifications),
        "risk_summary": _build_risk_summary(request.findings, effective_status_by_finding, severity_by_finding),
        "binary_protection_analysis": _build_binary_protection_analysis(request.evidence),
        "software_code_security": _build_software_code_security(
            request.findings,
            request.evidence,
            verifications_by_finding,
        ),
        "evidence": [item.model_dump(mode="json") for item in request.evidence],
        "verifications": [item.model_dump(mode="json") for item in request.verifications],
        "evidence_graph": build_evidence_graph(request.findings, request.evidence, request.verifications),
        "mock": bool(request.findings) and all(
            item.metadata.get("mock") for item in request.findings
        ),
        "limitations": {
            "missing_evidence_ids": sorted(missing_evidence_ids),
            "unverified_finding_ids": sorted(
                finding.vulnerability_id
                for finding in request.findings
                if finding.vulnerability_id not in verifications_by_finding
            ),
        }
    }


_SOFTWARE_CODE_TYPES = frozenset(
    {
        "integer_overflow",
        "integer_underflow",
        "integer_boundary_error",
        "buffer_overflow",
        "stack_buffer_overflow",
        "heap_buffer_overflow",
        "array_out_of_bounds",
        "input_validation_missing",
        "null_pointer_dereference",
        "resource_leak",
        "interface_access_control_missing",
        "configuration_authorization_missing",
    }
)


def _build_software_code_security(
    findings: list[VulnerabilityCandidate],
    evidence: list[Evidence],
    verifications: dict[str, VerificationResult],
) -> dict[str, Any]:
    """Build a deterministic dossier chapter from public contracts only."""

    selected = [
        finding
        for finding in findings
        if finding.metadata.get("audit_domain") == "software_code"
        or finding.vulnerability_type in _SOFTWARE_CODE_TYPES
    ]
    severity_counts = {label: 0 for label in _severity_labels()}
    type_counts: dict[str, int] = {}
    dossiers: list[dict[str, Any]] = []
    for finding in selected:
        severity_counts[severity_label(finding.severity)] += 1
        classified_type = str(finding.metadata.get("risk_subtype") or finding.vulnerability_type)
        type_counts[classified_type] = type_counts.get(classified_type, 0) + 1
        verification = verifications.get(finding.vulnerability_id)
        related = _evidence_for_finding(finding, verification, evidence)
        model_assessment = next(
            (
                item.data
                for item in related
                if item.evidence_type is EvidenceType.MODEL_REASONING_SUMMARY
                and item.source == "code_audit"
            ),
            None,
        )
        dynamic_result = next(
            (
                item.data
                for item in related
                if item.evidence_type in {
                    EvidenceType.RUNTIME_TRACE,
                    EvidenceType.CRASH_LOG,
                    EvidenceType.SANITIZER_OUTPUT,
                }
                and item.source == "controlled_robustness"
            ),
            None,
        )
        evidence_chain = []
        stages = (
            ("source_location", {EvidenceType.SOURCE_LOCATION}),
            ("control_flow_path", {EvidenceType.CFG_PATH}),
            ("taint_path", {EvidenceType.TAINT_PATH, EvidenceType.DATA_FLOW}),
            ("candidate_rule", {EvidenceType.TOOL_RESULT}),
            ("dynamic_validation", {EvidenceType.RUNTIME_TRACE, EvidenceType.CRASH_LOG, EvidenceType.SANITIZER_OUTPUT}),
            ("agent_assessment", {EvidenceType.MODEL_REASONING_SUMMARY}),
            ("independent_verification", {EvidenceType.VERIFICATION_RESULT}),
        )
        for stage, kinds in stages:
            for item in related:
                if item.evidence_type in kinds:
                    evidence_chain.append(
                        {
                            "stage": stage,
                            "evidence_id": item.evidence_id,
                            "source": item.source,
                            "description": item.description,
                        }
                    )
        location = finding.location.model_dump(mode="json") if finding.location else None
        generic_remediation = _remediation_block(
            finding,
            _effective_status(finding, verification),
            severity_rank(finding.severity),
        )
        dossiers.append(
            {
                "dossier_id": f"dossier-{finding.vulnerability_id}",
                "finding_id": finding.vulnerability_id,
                "vulnerability_type": finding.vulnerability_type,
                "risk_subtype": finding.metadata.get("risk_subtype"),
                "cwe_id": normalize_cwe(finding.cwe_id),
                "title": finding.title,
                "risk_level": severity_label(finding.severity),
                "status": _effective_status(finding, verification),
                "source_location": location,
                "control_flow_path": finding.metadata.get("cfg_path", []),
                "taint_path": finding.metadata.get("taint_path", []),
                "candidate_rule": {
                    "rule_id": finding.metadata.get("rule_id"),
                    "engine": finding.metadata.get("analysis_engine"),
                    "sink": finding.metadata.get("sink"),
                    "guard_observed": finding.metadata.get("guard_observed"),
                },
                "static_evidence": [
                    item.model_dump(mode="json")
                    for item in related
                    if item.evidence_type in {
                        EvidenceType.SOURCE_LOCATION,
                        EvidenceType.CODE_SNIPPET,
                        EvidenceType.CFG_PATH,
                        EvidenceType.TAINT_PATH,
                        EvidenceType.DATA_FLOW,
                        EvidenceType.TOOL_RESULT,
                    }
                ],
                "dynamic_validation": dynamic_result,
                "agent_assessment": model_assessment,
                "independent_verification": (
                    verification.model_dump(mode="json") if verification else None
                ),
                "remediation": {
                    **generic_remediation,
                    "agent_summary": (
                        model_assessment.get("remediation_summary")
                        if isinstance(model_assessment, dict)
                        else None
                    ),
                    "agent_actions": (
                        model_assessment.get("remediation_actions", [])
                        if isinstance(model_assessment, dict)
                        else []
                    ),
                },
                "evidence_chain": evidence_chain,
                "compliance_notice": COMPLIANCE_NOTICE,
            }
        )
    return {
        "title": "大模型服务代码安全审计",
        "finding_count": len(selected),
        "risk_level_distribution": severity_counts,
        "vulnerability_type_distribution": dict(sorted(type_counts.items())),
        "dossiers": dossiers,
        "compliance_notice": COMPLIANCE_NOTICE,
    }


def _evidence_for_finding(
    finding: VulnerabilityCandidate,
    verification: VerificationResult | None,
    evidence: list[Evidence],
) -> list[Evidence]:
    linked_ids = set(finding.evidence_ids)
    if verification is not None:
        linked_ids.update(verification.evidence_ids)
    return [
        item
        for item in evidence
        if item.evidence_id in linked_ids
        or item.data.get("finding_id") == finding.vulnerability_id
        or item.data.get("vulnerability_id") == finding.vulnerability_id
    ]


def _build_binary_protection_analysis(evidence: list[Evidence]) -> dict[str, Any] | None:
    """Build the dedicated protected-program chapter from evidence only."""

    restoration = next((item for item in evidence if item.source == "program_restoration"), None)
    deobfuscation = next((item for item in evidence if item.source == "code_deobfuscation"), None)
    reverse = next((item for item in evidence if item.source == "binary_reverse"), None)
    if restoration is None and deobfuscation is None and reverse is None:
        return None
    restore_data = restoration.data if restoration is not None else {}
    deobf_data = deobfuscation.data if deobfuscation is not None else {}
    reverse_data = reverse.data if reverse is not None else {}
    protection = restore_data.get("protection", {})
    selected = protection.get("selected") if isinstance(protection, dict) else None
    readability = deobf_data.get("readability", {})
    instruction_recovery = deobf_data.get("instruction_recovery", {})
    functions = instruction_recovery.get("functions", []) if isinstance(instruction_recovery, dict) else []
    validation = restore_data.get("validation", {})
    return {
        "title": "二进制程序保护分析专项",
        "protection": selected if isinstance(selected, dict) else None,
        "declared_protection": protection.get("declared_protection") if isinstance(protection, dict) else None,
        "strategy": restore_data.get("strategy", []),
        "restoration": {
            "status": restore_data.get("status", "not_run"),
            "success": bool(restore_data.get("success", False)),
            "metrics": restore_data.get("metrics", {}),
            "validation": validation if isinstance(validation, dict) else {},
            "records": restore_data.get("records", []),
        },
        "reverse_analysis": {
            "function_count": reverse_data.get("function_count", 0),
            "pseudocode_count": reverse_data.get("pseudocode_count", 0),
            "cfg_node_count": reverse_data.get("cfg_node_count", 0),
            "parseable": validation.get("parseable", bool(reverse)) if isinstance(validation, dict) else bool(reverse),
        },
        "deobfuscation": {
            "detected_types": deobf_data.get("detected_types", []),
            "readability": readability if isinstance(readability, dict) else {},
            "recovered_function_count": len(functions) if isinstance(functions, list) else 0,
            "string_count": deobf_data.get("string_recovery", {}).get("decoded_count", 0),
            "before_after_examples": functions[:3] if isinstance(functions, list) else [],
        },
        "evidence_chain": [
            {"stage": stage, "evidence_id": item.evidence_id, "source": item.source}
            for stage, item in (
                ("protection_identification_and_restoration", restoration),
                ("structure_and_decompilation", reverse),
                ("deobfuscation_and_readability", deobfuscation),
            )
            if item is not None
        ],
    }


def _effective_status(finding: VulnerabilityCandidate, verification: VerificationResult | None) -> str:
    if verification is not None:
        return verification.status.value
    return finding.status.value


def _severity_block(value: str | None) -> dict[str, Any]:
    return {
        "raw": value,
        "label": severity_label(value),
        "rank": severity_rank(value),
        "cn": severity_cn(value),
    }


def _reasoning_block(
    finding: VulnerabilityCandidate,
    verification: VerificationResult | None,
    effective_status: str,
    evidence_by_id: dict[str, Evidence],
) -> dict[str, Any]:
    verification_present = verification is not None
    based_on = sorted(
        evidence_id
        for evidence_id in (verification.evidence_ids if verification is not None else [])
        if evidence_id in evidence_by_id
    )
    return {
        "verification_present": verification_present,
        "verified": verification_present,
        "status": effective_status,
        "confidence": verification.confidence if verification is not None else None,
        "rationale": verification.rationale if verification is not None else None,
        "based_on_evidence_ids": based_on,
        "note": _REASONING_NOTES.get(effective_status, _UNVERIFIED_NOTE),
    }


def _remediation_block(finding: VulnerabilityCandidate, effective_status: str, rank: int) -> dict[str, Any]:
    priority, priority_label = remediation_priority(rank, effective_status)
    guidance, knowledge_source = guidance_for(finding.cwe_id, finding.vulnerability_type, effective_status)
    return {
        "priority": priority,
        "priority_label": priority_label,
        "status": effective_status,
        "guidance": guidance,
        "knowledge_source": knowledge_source,
        "disclaimer": DISCLAIMER,
    }


def _severity_labels() -> list[str]:
    return [*SEVERITY_ORDER, "UNKNOWN"]


def _build_severity_distribution(findings: list[VulnerabilityCandidate]) -> dict[str, int]:
    counts = {label: 0 for label in _severity_labels()}
    for finding in findings:
        counts[severity_label(finding.severity)] += 1
    return counts


def _build_severity_ordered_ids(findings: list[VulnerabilityCandidate]) -> list[str]:
    ordered = sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity), f.vulnerability_id),
    )
    return [finding.vulnerability_id for finding in ordered]


def _build_cwe_classification(findings: list[VulnerabilityCandidate]) -> dict[str, Any]:
    buckets: dict[str | None, dict[str, Any]] = {}
    for finding in findings:
        canonical = normalize_cwe(finding.cwe_id)
        bucket = buckets.setdefault(canonical, {
            "cwe_id": canonical,
            "cwe_label": canonical if canonical is not None else "未关联CWE",
            "count": 0,
            "max_severity_rank": 0,
            "severity_counts": {label: 0 for label in _severity_labels()},
            "_members": [],
        })
        rank = severity_rank(finding.severity)
        bucket["count"] += 1
        bucket["max_severity_rank"] = max(bucket["max_severity_rank"], rank)
        bucket["severity_counts"][severity_label(finding.severity)] += 1
        bucket["_members"].append((rank, finding.vulnerability_id))

    groups: list[dict[str, Any]] = []
    none_bucket: dict[str, Any] | None = None
    for canonical, bucket in buckets.items():
        members = sorted(bucket.pop("_members"), key=lambda item: (-item[0], item[1]))
        group = {
            "cwe_id": bucket["cwe_id"],
            "cwe_label": bucket["cwe_label"],
            "count": bucket["count"],
            "max_severity": severity_label_from_rank(bucket["max_severity_rank"]),
            "max_severity_rank": bucket["max_severity_rank"],
            "severity_counts": bucket["severity_counts"],
            "finding_ids": [finding_id for _, finding_id in members],
        }
        if canonical is None:
            none_bucket = group
        else:
            groups.append(group)

    groups.sort(key=lambda g: (-g["count"], g["cwe_id"]))
    if none_bucket is not None:
        groups.append(none_bucket)
    return {"groups": groups}


def _utc_epoch(value: datetime) -> float:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def _build_evidence_timeline(
    evidence: list[Evidence],
    findings: list[VulnerabilityCandidate],
    verifications: list[VerificationResult],
) -> list[dict[str, Any]]:
    findings_by_evidence: dict[str, set[str]] = {}
    verifications_by_evidence: dict[str, set[str]] = {}
    for finding in findings:
        for evidence_id in finding.evidence_ids:
            findings_by_evidence.setdefault(evidence_id, set()).add(finding.vulnerability_id)
    for verification in verifications:
        for evidence_id in verification.evidence_ids:
            verifications_by_evidence.setdefault(evidence_id, set()).add(verification.vulnerability_id)
    for item in evidence:
        direct_id = item.data.get("finding_id") or item.data.get("vulnerability_id")
        if isinstance(direct_id, str):
            findings_by_evidence.setdefault(item.evidence_id, set()).add(direct_id)

    ordered = sorted(evidence, key=lambda item: (_utc_epoch(item.created_at), item.evidence_id))
    timeline: list[dict[str, Any]] = []
    for item in ordered:
        timeline.append({
            "evidence_id": item.evidence_id,
            "timestamp": item.model_dump(mode="json")["created_at"],
            "evidence_type": item.evidence_type.value,
            "source": item.source,
            "created_by": item.created_by,
            "reliability": item.reliability,
            "description": item.description,
            "linked_finding_ids": sorted(findings_by_evidence.get(item.evidence_id, set())),
            "linked_verification_ids": sorted(verifications_by_evidence.get(item.evidence_id, set())),
        })
    return timeline


def _build_risk_summary(
    findings: list[VulnerabilityCandidate],
    effective_status_by_finding: dict[str, str],
    severity_by_finding: dict[str, int],
) -> dict[str, Any]:
    by_status = {status.value: 0 for status in VulnerabilityStatus}
    for finding in findings:
        by_status[effective_status_by_finding[finding.vulnerability_id]] += 1

    total = len(findings)
    confirmed = by_status["confirmed"]
    rejected = by_status["rejected"]
    pending = by_status["candidate"] + by_status["verifying"] + by_status["uncertain"]
    actionable = total - rejected

    actionable_findings = [
        finding
        for finding in findings
        if effective_status_by_finding[finding.vulnerability_id] != "rejected"
    ]
    overall_rank = max((severity_by_finding[finding.vulnerability_id] for finding in actionable_findings), default=0)
    if actionable_findings:
        overall_level = severity_label_from_rank(overall_rank)
        overall_level_cn = severity_cn(overall_level)
    else:
        overall_level = "NONE"
        overall_level_cn = "无"

    if not actionable_findings:
        headline = f"本次扫描共 {total} 项发现，均已由验证排除（rejected），未发现需要修复的风险项。"
    else:
        headline = (
            f"本次扫描共 {total} 项发现，最高风险等级为“{overall_level_cn}”；"
            f"其中已确认 {confirmed} 项、已排除 {rejected} 项、另有 {pending} 项待复核。"
        )

    ordered = sorted(
        actionable_findings,
        key=lambda f: (
            -severity_by_finding[f.vulnerability_id],
            0 if effective_status_by_finding[f.vulnerability_id] in _FINAL_STATUSES else 1,
            -f.confidence,
            f.vulnerability_id,
        ),
    )
    top_risks = [
        {
            "vulnerability_id": finding.vulnerability_id,
            "title": finding.title,
            "severity": severity_label(finding.severity),
            "severity_rank": severity_by_finding[finding.vulnerability_id],
            "status": effective_status_by_finding[finding.vulnerability_id],
            "cwe_id": normalize_cwe(finding.cwe_id),
            "confidence": finding.confidence,
        }
        for finding in ordered[:TOP_RISKS_LIMIT]
    ]

    return {
        "overall_level": overall_level,
        "overall_level_rank": overall_rank,
        "overall_level_cn": overall_level_cn,
        "headline": headline,
        "counts": {
            "total": total,
            "confirmed": confirmed,
            "rejected": rejected,
            "pending": pending,
            "actionable": actionable,
            "by_status": by_status,
        },
        "top_risks": top_risks,
    }
