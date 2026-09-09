"""Tests for the enriched structured report sections.

Covers CWE classification, severity distribution/ordering, the evidence
timeline, per-finding verification reasoning, the risk summary (including
rejected-finding handling) and remediation guidance, plus JSON serialisability.
The existing ``test_structured_report.py`` stays untouched as regression.
"""

import json
from datetime import date, datetime, timezone
from enum import Enum

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    ReportRequest,
    Target,
    TargetType,
    Task,
    VerificationResult,
    VulnerabilityCandidate,
    VulnerabilityStatus,
)
from vulnagent.report.generator import MockReportGenerator
from vulnagent.report.remediation import DISCLAIMER, REJECTED_GUIDANCE

_UTC = timezone.utc


def _task(task_id: str = "task-1") -> Task:
    return Task(task_id=task_id, target=Target(target_id="target-1", path="fixture.py", target_type=TargetType.SOURCE))


def _finding(
    vid: str,
    *,
    severity: str | None = None,
    cwe_id: str | None = None,
    status: VulnerabilityStatus = VulnerabilityStatus.CANDIDATE,
    vulnerability_type: str = "injection",
    confidence: float = 0.7,
    evidence_ids: list[str] | None = None,
    title: str | None = None,
) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id=vid,
        task_id="task-1",
        title=title or f"finding {vid}",
        vulnerability_type=vulnerability_type,
        description="fixture finding",
        target_id="target-1",
        source_agent="audit",
        confidence=confidence,
        severity=severity,
        cwe_id=cwe_id,
        status=status,
        evidence_ids=evidence_ids or [],
    )


def _evidence(eid: str, *, created_at: datetime | None = None) -> Evidence:
    return Evidence(
        evidence_id=eid,
        task_id="task-1",
        evidence_type=EvidenceType.SOURCE_LOCATION,
        source="audit",
        description=f"evidence {eid}",
        reliability=0.8,
        created_by="audit",
        created_at=created_at or datetime(2026, 9, 10, tzinfo=_UTC),
    )


def _verification(
    vid: str,
    *,
    status: VulnerabilityStatus = VulnerabilityStatus.CONFIRMED,
    confidence: float = 0.9,
    rationale: str = "reproduced in a controlled run",
    evidence_ids: list[str] | None = None,
) -> VerificationResult:
    return VerificationResult(
        vulnerability_id=vid,
        task_id="task-1",
        status=status,
        confidence=confidence,
        rationale=rationale,
        evidence_ids=evidence_ids or [],
    )


async def test_cwe_classification_groups_and_unclassified_bucket_last() -> None:
    findings = [
        _finding("f1", severity="HIGH", cwe_id="cwe-120"),
        _finding("f2", severity="CRITICAL", cwe_id="CWE-89"),
        _finding("f3", severity="LOW", cwe_id=None, status=VulnerabilityStatus.REJECTED),
    ]
    report = await MockReportGenerator().generate(ReportRequest(task=_task(), findings=findings))

    groups = report.content["cwe_classification"]["groups"]
    assert len(groups) == 3
    # The unclassified bucket always comes last.
    assert groups[-1]["cwe_id"] is None
    assert groups[-1]["cwe_label"] == "未关联CWE"
    assert groups[-1]["finding_ids"] == ["f3"]

    by_cwe = {group["cwe_id"]: group for group in groups}
    group_120 = by_cwe["CWE-120"]  # normalized from "cwe-120"
    assert group_120["count"] == 1
    assert group_120["max_severity"] == "HIGH"
    assert group_120["max_severity_rank"] == 4
    assert group_120["finding_ids"] == ["f1"]
    assert group_120["severity_counts"]["HIGH"] == 1
    assert by_cwe["CWE-89"]["max_severity"] == "CRITICAL"


async def test_severity_distribution_ordering_and_input_order_preserved() -> None:
    findings = [
        _finding("fA", severity="CRITICAL"),
        _finding("fB", severity="MEDIUM"),
        _finding("fC", severity=None),
        _finding("fD", severity="INFO"),
        _finding("fE", severity="HIGH"),
    ]
    report = await MockReportGenerator().generate(ReportRequest(task=_task(), findings=findings))

    summary = report.content["summary"]
    assert summary["findings_by_severity"] == {
        "CRITICAL": 1,
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 0,
        "INFO": 1,
        "UNKNOWN": 1,
    }
    assert summary["severity_ordered_finding_ids"] == ["fA", "fE", "fB", "fD", "fC"]

    # The findings[] array keeps the input order; ordering is exposed separately.
    assert [row["finding"]["vulnerability_id"] for row in report.content["findings"]] == ["fA", "fB", "fC", "fD", "fE"]

    rows = {row["finding"]["vulnerability_id"]: row["severity"] for row in report.content["findings"]}
    assert rows["fA"] == {"raw": "CRITICAL", "label": "CRITICAL", "rank": 5, "cn": "严重"}
    assert rows["fC"] == {"raw": None, "label": "UNKNOWN", "rank": 0, "cn": "未知"}


async def test_evidence_timeline_is_chronological_with_deterministic_tie_break() -> None:
    early = _evidence("e-early", created_at=datetime(2026, 9, 10, 0, tzinfo=_UTC))
    same_time = datetime(2026, 9, 10, 10, tzinfo=_UTC)
    zeta = _evidence("e-zeta", created_at=same_time)
    alpha = _evidence("e-alpha", created_at=same_time)

    finding = _finding("f1", severity="HIGH", evidence_ids=["e-early", "e-zeta"])
    verification = _verification("f1", evidence_ids=["e-zeta"])

    # Feed a deliberately scrambled order; output must be canonical.
    report = await MockReportGenerator().generate(ReportRequest(
        task=_task(),
        findings=[finding],
        evidence=[zeta, early, alpha],
        verifications=[verification],
    ))

    timeline = report.content["evidence_timeline"]
    assert [entry["evidence_id"] for entry in timeline] == ["e-early", "e-alpha", "e-zeta"]
    assert all(isinstance(entry["timestamp"], str) for entry in timeline)

    by_id = {entry["evidence_id"]: entry for entry in timeline}
    assert by_id["e-early"]["linked_finding_ids"] == ["f1"]
    assert by_id["e-early"]["linked_verification_ids"] == []
    assert by_id["e-zeta"]["linked_finding_ids"] == ["f1"]
    assert by_id["e-zeta"]["linked_verification_ids"] == ["f1"]
    assert by_id["e-alpha"]["linked_finding_ids"] == []
    assert by_id["e-early"]["evidence_type"] == "source_location"
    assert by_id["e-early"]["created_by"] == "audit"


async def test_evidence_timeline_accepts_naive_timestamps() -> None:
    evidence = _evidence("e-naive", created_at=datetime(2026, 9, 10, 3, 0))
    report = await MockReportGenerator().generate(ReportRequest(task=_task(), evidence=[evidence]))

    timeline = report.content["evidence_timeline"]
    assert len(timeline) == 1
    assert timeline[0]["evidence_id"] == "e-naive"
    assert isinstance(timeline[0]["timestamp"], str)


async def test_per_finding_verification_reasoning_verified_and_unverified() -> None:
    store = [_evidence("evidence-1")]
    verified = _finding("f1", severity="HIGH", evidence_ids=["evidence-1"])
    unverified = _finding("f2", severity="MEDIUM")
    verification = _verification("f1", rationale="reproduced safely", evidence_ids=["evidence-1"])

    report = await MockReportGenerator().generate(ReportRequest(
        task=_task(),
        findings=[verified, unverified],
        evidence=store,
        verifications=[verification],
    ))

    reasoning = {row["finding"]["vulnerability_id"]: row["reasoning"] for row in report.content["findings"]}
    assert reasoning["f1"]["verification_present"] is True
    assert reasoning["f1"]["verified"] is True
    assert reasoning["f1"]["status"] == "confirmed"
    assert reasoning["f1"]["confidence"] == 0.9
    assert reasoning["f1"]["rationale"] == "reproduced safely"
    assert reasoning["f1"]["based_on_evidence_ids"] == ["evidence-1"]
    assert "确认" in reasoning["f1"]["note"]

    assert reasoning["f2"]["verification_present"] is False
    assert reasoning["f2"]["verified"] is False
    assert reasoning["f2"]["status"] == "candidate"
    assert reasoning["f2"]["confidence"] is None
    assert reasoning["f2"]["rationale"] is None
    assert reasoning["f2"]["based_on_evidence_ids"] == []
    assert "尚未经过独立验证" in reasoning["f2"]["note"]


async def test_risk_summary_excludes_rejected_findings() -> None:
    findings = [
        _finding("r1", severity="CRITICAL", status=VulnerabilityStatus.REJECTED),
        _finding("r2", severity="HIGH"),
        _finding("r3", severity="MEDIUM"),
    ]
    verification = _verification("r2")

    report = await MockReportGenerator().generate(ReportRequest(
        task=_task(),
        findings=findings,
        verifications=[verification],
    ))

    risk = report.content["risk_summary"]
    assert risk["overall_level"] == "HIGH"  # the rejected CRITICAL finding does not drive the level
    assert risk["overall_level_rank"] == 4
    assert risk["overall_level_cn"] == "高"
    assert "最高风险等级为“高”" in risk["headline"]
    assert "已确认 1 项" in risk["headline"]
    assert "已排除 1 项" in risk["headline"]

    assert risk["counts"]["total"] == 3
    assert risk["counts"]["confirmed"] == 1
    assert risk["counts"]["rejected"] == 1
    assert risk["counts"]["pending"] == 1
    assert risk["counts"]["actionable"] == 2

    top_risk_ids = [entry["vulnerability_id"] for entry in risk["top_risks"]]
    assert top_risk_ids == ["r2", "r3"]
    assert risk["top_risks"][0]["status"] == "confirmed"


async def test_risk_summary_is_none_when_all_findings_rejected() -> None:
    findings = [
        _finding("r1", severity="CRITICAL", status=VulnerabilityStatus.REJECTED),
        _finding("r2", severity="HIGH", status=VulnerabilityStatus.REJECTED),
    ]
    report = await MockReportGenerator().generate(ReportRequest(task=_task(), findings=findings))

    risk = report.content["risk_summary"]
    assert risk["overall_level"] == "NONE"
    assert risk["overall_level_rank"] == 0
    assert risk["overall_level_cn"] == "无"
    assert risk["counts"]["rejected"] == 2
    assert risk["counts"]["actionable"] == 0
    assert risk["top_risks"] == []
    assert "均已由验证排除（rejected）" in risk["headline"]


async def test_remediation_priority_sources_and_disclaimer() -> None:
    findings = [
        _finding("a", severity="CRITICAL", cwe_id="cwe-120"),                       # CWE-120, confirmed
        _finding("b", severity="HIGH", cwe_id=None, vulnerability_type="command_injection"),  # type fallback, candidate
        _finding("c", severity="MEDIUM", cwe_id=None, vulnerability_type="exotic_future"),     # generic, confirmed
        _finding("d", severity="CRITICAL", cwe_id="CWE-120", status=VulnerabilityStatus.REJECTED),
    ]
    verifications = [_verification("a"), _verification("c")]

    report = await MockReportGenerator().generate(ReportRequest(
        task=_task(),
        findings=findings,
        verifications=verifications,
    ))

    remediation = {row["finding"]["vulnerability_id"]: row["remediation"] for row in report.content["findings"]}

    assert remediation["a"]["knowledge_source"] == "CWE-120"
    assert remediation["a"]["priority"] == 0
    assert remediation["a"]["priority_label"] == "P0·紧急"
    assert remediation["a"]["guidance"]

    assert remediation["b"]["knowledge_source"] == "type:command_injection"
    assert remediation["b"]["priority_label"] == "P2·中"  # HIGH + not-final status is down-weighted

    assert remediation["c"]["knowledge_source"] == "generic"
    assert remediation["c"]["priority_label"] == "P2·中"

    assert remediation["d"]["knowledge_source"] == "rejected"
    assert remediation["d"]["priority"] == 5
    assert remediation["d"]["priority_label"] == "无需处理"
    assert remediation["d"]["guidance"] == REJECTED_GUIDANCE

    for block in remediation.values():
        assert block["disclaimer"] == DISCLAIMER
        assert block["disclaimer"]


async def test_content_is_json_serialisable_and_backward_compatible() -> None:
    finding = _finding("f1", severity="HIGH", cwe_id="CWE-120", evidence_ids=["evidence-1", "missing"])
    evidence = _evidence("evidence-1", created_at=datetime(2026, 9, 10, tzinfo=_UTC))
    verification = _verification("f1", evidence_ids=["evidence-1"])

    report = await MockReportGenerator().generate(ReportRequest(
        task=_task(),
        findings=[finding],
        evidence=[evidence],
        verifications=[verification],
    ))

    # Old paths still present.
    assert report.content["summary"]["finding_count"] == 1
    assert report.content["findings"][0]["verification"]["status"] == "confirmed"
    assert report.content["limitations"]["missing_evidence_ids"] == ["missing"]
    assert report.content["evidence_graph"]["edges"]
    for key in ("task", "findings", "evidence", "verifications", "evidence_graph", "limitations", "mock", "cwe_classification", "evidence_timeline", "risk_summary"):
        assert key in report.content
    for key in ("finding", "verification", "evidence", "severity", "reasoning", "remediation"):
        assert key in report.content["findings"][0]

    dumped = json.dumps(report.content, ensure_ascii=False, allow_nan=False)
    assert dumped

    def _walk(value) -> None:
        if isinstance(value, dict):
            for child in value.values():
                _walk(child)
        elif isinstance(value, list):
            for child in value:
                _walk(child)
        else:
            assert not isinstance(value, (datetime, date, Enum, set)), type(value)

    _walk(report.content)
