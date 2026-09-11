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
    story: list[Any] = [
        para(title, title_style),
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
        para("漏洞发现与独立复核", heading),
    ]

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
        canvas.drawString(18 * mm, 9 * mm, f"VulnAgent · Task {_text(task.get('task_id'))}")
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"第 {document.page} 页")
        canvas.restoreState()

    try:
        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination
