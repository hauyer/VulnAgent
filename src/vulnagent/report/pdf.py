"""Printable PDF projection of the existing structured report."""

from __future__ import annotations

import html
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def write_report_pdf(
    report: Mapping[str, Any],
    output_path: Path,
    *,
    title: str = "VulnAgent 漏洞分析报告",
) -> Path:
    """Atomically write a self-contained PDF from structured report fields.

    ReportLab is imported lazily so the core service remains usable when the
    optional ``report-export`` dependency is not installed.
    """

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        from reportlab.platypus import (
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - exercised in minimal installs
        raise RuntimeError(
            'PDF export requires: python -m pip install -e ".[report-export]"'
        ) from exc

    try:
        pdfmetrics.getFont("STSong-Light")
    except KeyError:
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))

    destination = output_path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "VulnAgentBody",
        parent=styles["BodyText"],
        fontName="STSong-Light",
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#243047"),
        spaceAfter=4,
    )
    muted = ParagraphStyle(
        "VulnAgentMuted",
        parent=body,
        fontSize=7.5,
        leading=11,
        textColor=colors.HexColor("#667085"),
    )
    heading = ParagraphStyle(
        "VulnAgentHeading",
        parent=body,
        fontSize=15,
        leading=20,
        textColor=colors.HexColor("#1f3a8a"),
        spaceBefore=10,
        spaceAfter=8,
    )
    finding_heading = ParagraphStyle(
        "VulnAgentFindingHeading",
        parent=body,
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#172554"),
        spaceAfter=5,
    )
    title_style = ParagraphStyle(
        "VulnAgentTitle",
        parent=body,
        fontSize=22,
        leading=29,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17348a"),
        spaceAfter=14,
    )

    def para(value: Any, style: Any = body) -> Any:
        safe = html.escape(_text(value), quote=True).replace("\n", "<br/>")
        return Paragraph(safe, style)

    def table(data: list[list[Any]], widths: list[float] | None = None) -> Any:
        item = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        item.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9efff")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#17348a")),
                    ("FONTNAME", (0, 0), (-1, -1), "STSong-Light"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("LEADING", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d8e0ef")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8faff")]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return item

    task = _mapping(report.get("task"))
    target = _mapping(task.get("target"))
    summary = _mapping(report.get("summary"))
    risk = _mapping(report.get("risk_summary"))
    counts = _mapping(risk.get("counts"))
    compliance_notice = report.get("compliance_notice") or "仅用于安全审计与防御研究，仅限教学实验使用"
    story: list[Any] = [
        para(title, title_style),
        para(compliance_notice, muted),
        table(
            [
                [para("Task", muted), para("Target", muted), para("类型", muted), para("状态", muted)],
                [
                    para(task.get("task_id")),
                    para(target.get("target_id")),
                    para(target.get("target_type")),
                    para(task.get("status")),
                ],
            ],
            [42 * mm, 56 * mm, 28 * mm, 34 * mm],
        ),
        Spacer(1, 4 * mm),
        table(
            [
                [para("Findings", muted), para("Evidence", muted), para("Confirmed", muted), para("Rejected", muted), para("最高风险", muted)],
                [
                    para(summary.get("finding_count", 0)),
                    para(summary.get("evidence_count", 0)),
                    para(counts.get("confirmed", 0)),
                    para(counts.get("rejected", 0)),
                    para(risk.get("overall_level") or "NONE"),
                ],
            ],
            [32 * mm] * 5,
        ),
        para("任务与风险摘要", heading),
        para(risk.get("headline")),
        para(f"目标路径：{_text(target.get('path'))}", muted),
        para(f"创建时间：{_text(task.get('created_at'))}", muted),
    ]

    binary_protection = _mapping(report.get("binary_protection_analysis"))
    if binary_protection:
        protection = _mapping(binary_protection.get("protection"))
        restoration = _mapping(binary_protection.get("restoration"))
        validation = _mapping(restoration.get("validation"))
        metrics = _mapping(restoration.get("metrics"))
        deobfuscation = _mapping(binary_protection.get("deobfuscation"))
        readability = _mapping(deobfuscation.get("readability"))
        story.extend(
            [
                para(binary_protection.get("title") or "二进制程序保护分析专项", heading),
                table(
                    [
                        [para("保护类型", muted), para("强度", muted), para("还原状态", muted), para("可解析", muted), para("耗时", muted)],
                        [
                            para(protection.get("family") or "未归因"),
                            para(f"L{_text(protection.get('level') or 0)}"),
                            para(restoration.get("status") or "not_run"),
                            para(bool(validation.get("parseable"))),
                            para(f"{_text(metrics.get('elapsed_ms') or 0)} ms"),
                        ],
                    ],
                    [34 * mm, 24 * mm, 38 * mm, 28 * mm, 36 * mm],
                ),
                para(
                    "混淆类型：{types}　可读性：{before} → {after}".format(
                        types="、".join(map(_text, _list(deobfuscation.get("detected_types")))) or "未检出",
                        before=_text(readability.get("before") or 0),
                        after=_text(readability.get("after") or 0),
                    )
                ),
            ]
        )
        chain_data = [[para("阶段", muted), para("Evidence ID", muted), para("来源", muted)]]
        for raw_item in _list(binary_protection.get("evidence_chain")):
            item = _mapping(raw_item)
            chain_data.append([
                para(item.get("stage"), muted),
                para(item.get("evidence_id"), muted),
                para(item.get("source"), muted),
            ])
        if len(chain_data) > 1:
            story.append(table(chain_data, [66 * mm, 55 * mm, 39 * mm]))

    software_code = _mapping(report.get("software_code_security"))
    if software_code:
        distribution = _mapping(software_code.get("risk_level_distribution"))
        story.extend(
            [
                para(software_code.get("title") or "大模型服务代码安全审计", heading),
                para(software_code.get("compliance_notice"), muted),
                table(
                    [
                        [para("代码风险", muted), para("高风险", muted), para("中风险", muted), para("低风险", muted)],
                        [
                            para(software_code.get("finding_count", 0)),
                            para(distribution.get("HIGH", 0)),
                            para(distribution.get("MEDIUM", 0)),
                            para(distribution.get("LOW", 0)),
                        ],
                    ],
                    [40 * mm] * 4,
                ),
            ]
        )
        for raw_dossier in _list(software_code.get("dossiers")):
            dossier = _mapping(raw_dossier)
            location = _mapping(dossier.get("source_location"))
            assessment = _mapping(dossier.get("agent_assessment"))
            dynamic = _mapping(dossier.get("dynamic_validation"))
            remediation = _mapping(dossier.get("remediation"))
            block = [
                para(dossier.get("title"), finding_heading),
                para(
                    "类型：{kind}　等级：{severity}　状态：{status}　CWE：{cwe}".format(
                        kind=_text(dossier.get("vulnerability_type")),
                        severity=_text(dossier.get("risk_level")),
                        status=_text(dossier.get("status")),
                        cwe=_text(dossier.get("cwe_id")),
                    ),
                    muted,
                ),
                para(
                    "源码定位：{file} · {function} · line {line}".format(
                        file=_text(location.get("file_path")),
                        function=_text(location.get("function_name")),
                        line=_text(location.get("line_start")),
                    )
                ),
                para("智能体研判：" + _text(assessment.get("summary") or "尚无")),
                para(
                    "受控验证："
                    + (
                        "用例 {cases}，异常 {anomalies}，环境已重置：{reset}".format(
                            cases=_text(dynamic.get("case_count", 0)),
                            anomalies=_text(dynamic.get("anomaly_count", 0)),
                            reset=_text(dynamic.get("reset_completed", False)),
                        )
                        if dynamic
                        else "未执行"
                    )
                ),
                para(
                    "修复方向："
                    + _text(
                        assessment.get("remediation_summary")
                        or remediation.get("agent_summary")
                        or remediation.get("priority_label")
                    )
                ),
            ]
            chain_data = [[para("阶段", muted), para("Evidence ID", muted), para("来源", muted)]]
            for raw_item in _list(dossier.get("evidence_chain")):
                item = _mapping(raw_item)
                chain_data.append(
                    [
                        para(item.get("stage"), muted),
                        para(item.get("evidence_id"), muted),
                        para(item.get("source"), muted),
                    ]
                )
            if len(chain_data) > 1:
                block.append(table(chain_data, [55 * mm, 65 * mm, 40 * mm]))
            story.extend([KeepTogether(block), Spacer(1, 4 * mm)])

    story.append(para("漏洞发现与独立复核", heading))

    finding_rows = _list(report.get("findings"))
    if not finding_rows:
        story.append(para("本次报告没有漏洞发现。"))
    for index, raw_row in enumerate(finding_rows, 1):
        row = _mapping(raw_row)
        finding = _mapping(row.get("finding"))
        severity = _mapping(row.get("severity"))
        reasoning = _mapping(row.get("reasoning"))
        verification = _mapping(row.get("verification"))
        remediation = _mapping(row.get("remediation"))
        location = _mapping(finding.get("location"))
        overview = [
            para(f"#{index}  {_text(finding.get('title'))}", finding_heading),
            para(
                "Severity: {severity}　Status: {status}　CWE: {cwe}　Confidence: {confidence}".format(
                    severity=_text(severity.get("label") or finding.get("severity")),
                    status=_text(reasoning.get("status") or finding.get("status")),
                    cwe=_text(finding.get("cwe_id")),
                    confidence=_text(finding.get("confidence")),
                ),
                muted,
            ),
            para(
                "位置：{file} · {function} · line {line} · {address}".format(
                    file=_text(location.get("file_path")),
                    function=_text(location.get("function_name")),
                    line=_text(location.get("line_start")),
                    address=_text(location.get("binary_address")),
                ),
                muted,
            ),
            para(finding.get("description")),
            table(
                [
                    [para("独立复核", muted), para("修复建议", muted)],
                    [
                        para(
                            "{note}\n依据：{rationale}\n复核置信度：{confidence}".format(
                                note=_text(reasoning.get("note")),
                                rationale=_text(
                                    verification.get("rationale")
                                    or reasoning.get("rationale")
                                ),
                                confidence=_text(
                                    verification.get("confidence")
                                    or reasoning.get("confidence")
                                ),
                            )
                        ),
                        para(
                            "{priority}\n{guidance}\n{disclaimer}".format(
                                priority=_text(remediation.get("priority_label")),
                                guidance="；".join(
                                    _text(item)
                                    for item in _list(remediation.get("guidance"))
                                )
                                or _text(remediation.get("guidance")),
                                disclaimer=_text(remediation.get("disclaimer")),
                            )
                        ),
                    ],
                ],
                [80 * mm, 80 * mm],
            ),
        ]
        evidence_data = [
            [para("Evidence ID", muted), para("类型", muted), para("来源", muted), para("可靠度", muted), para("说明", muted)]
        ]
        for raw_evidence in _list(row.get("evidence")):
            evidence = _mapping(raw_evidence)
            evidence_data.append(
                [
                    para(evidence.get("evidence_id"), muted),
                    para(evidence.get("evidence_type"), muted),
                    para(evidence.get("source"), muted),
                    para(evidence.get("reliability"), muted),
                    para(evidence.get("description"), muted),
                ]
            )
        if len(evidence_data) > 1:
            overview.extend(
                [
                    Spacer(1, 2 * mm),
                    table(evidence_data, [39 * mm, 25 * mm, 28 * mm, 16 * mm, 52 * mm]),
                ]
            )
        story.extend([KeepTogether(overview), Spacer(1, 5 * mm)])

    story.extend([PageBreak(), para("Evidence 时间线", heading)])
    timeline_data = [
        [para("时间", muted), para("Evidence ID", muted), para("类型", muted), para("来源", muted), para("说明", muted)]
    ]
    for raw_item in _list(report.get("evidence_timeline")):
        item = _mapping(raw_item)
        timeline_data.append(
            [
                para(item.get("timestamp"), muted),
                para(item.get("evidence_id"), muted),
                para(item.get("evidence_type"), muted),
                para(item.get("source"), muted),
                para(item.get("description"), muted),
            ]
        )
    if len(timeline_data) == 1:
        story.append(para("无 Evidence 时间线。"))
    else:
        story.append(table(timeline_data, [28 * mm, 39 * mm, 24 * mm, 27 * mm, 42 * mm]))

    limitations = _mapping(report.get("limitations"))
    missing = _list(limitations.get("missing_evidence_ids"))
    unverified = _list(limitations.get("unverified_finding_ids"))
    story.extend(
        [
            para("限制与完整性检查", heading),
            para("缺失 Evidence ID：" + (", ".join(map(_text, missing)) if missing else "无")),
            para("尚未独立复核 Finding：" + (", ".join(map(_text, unverified)) if unverified else "无")),
            para("本报告是结构化事实的展示层，不等同于漏洞可利用性证明。", muted),
        ]
    )

    doc = SimpleDocTemplate(
        str(temporary),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=17 * mm,
        title=title,
        author="VulnAgent",
    )

    def footer(canvas: Any, document: Any) -> None:
        canvas.saveState()
        canvas.setTitle(title)
        canvas.setAuthor("VulnAgent")
        canvas.setFont("STSong-Light", 7)
        canvas.setFillColor(colors.HexColor("#697386"))
        canvas.drawString(18 * mm, 9 * mm, "仅用于安全审计与防御研究 · 教学实验")
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"第 {document.page} 页")
        canvas.restoreState()

    try:
        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination
