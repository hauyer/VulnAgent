"""Offline, escaped HTML projection of the existing structured report."""

from __future__ import annotations

import html
from collections.abc import Mapping
from pathlib import Path
from typing import Any


_STATUS_CN = {
    "confirmed": "已确认",
    "rejected": "已排除",
    "uncertain": "待人工复核",
    "candidate": "候选",
    "verifying": "复核中",
}


def _escape(value: Any) -> str:
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        value = str(value).lower()
    return html.escape(str(value), quote=True)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _display_path(value: Any) -> Any:
    """Prefer repository-relative paths in portable offline reports."""

    if not isinstance(value, str) or not value:
        return value
    candidate = Path(value)
    if not candidate.is_absolute():
        return candidate.as_posix()
    repository_root = Path(__file__).resolve().parents[3]
    try:
        return candidate.resolve().relative_to(repository_root).as_posix()
    except (OSError, ValueError):
        return value


def _guidance(value: Any) -> str:
    items = _list(value)
    if items:
        return '<ul class="guidance">{}</ul>'.format(
            "".join(f"<li>{_escape(item)}</li>" for item in items)
        )
    return f"<p>{_escape(value)}</p>"


def _finding_cards(rows: list[Any]) -> str:
    if not rows:
        return '<div class="empty">本次报告没有漏洞发现。</div>'
    cards: list[str] = []
    for index, raw_row in enumerate(rows, 1):
        row = _mapping(raw_row)
        finding = _mapping(row.get("finding"))
        severity = _mapping(row.get("severity"))
        reasoning = _mapping(row.get("reasoning"))
        remediation = _mapping(row.get("remediation"))
        verification = _mapping(row.get("verification"))
        location = _mapping(finding.get("location"))
        status = str(reasoning.get("status") or finding.get("status") or "candidate")
        status_label = _STATUS_CN.get(status, status)
        evidence_rows = []
        for evidence in _list(row.get("evidence")):
            item = _mapping(evidence)
            evidence_rows.append(
                "<tr><td><code>{id}</code></td><td>{kind}</td><td>{source}</td>"
                "<td>{reliability}</td><td>{description}</td></tr>".format(
                    id=_escape(item.get("evidence_id")),
                    kind=_escape(item.get("evidence_type")),
                    source=_escape(item.get("source")),
                    reliability=_escape(item.get("reliability")),
                    description=_escape(item.get("description")),
                )
            )
        evidence_html = (
            "<table><thead><tr><th>Evidence ID</th><th>类型</th><th>来源</th>"
            "<th>可靠度</th><th>说明</th></tr></thead><tbody>{}</tbody></table>".format(
                "".join(evidence_rows)
            )
            if evidence_rows
            else '<div class="empty">没有可展示的关联 Evidence。</div>'
        )
        location_text = " · ".join(
            part
            for part in (
                str(_display_path(location.get("file_path")) or ""),
                str(location.get("function_name") or ""),
                f"line {location['line_start']}" if location.get("line_start") else "",
                str(location.get("binary_address") or ""),
            )
            if part
        )
        cards.append(
            """
<article class="finding">
  <div class="finding-head">
    <div><span class="index">#{index}</span><h3>{title}</h3></div>
    <div class="badges"><span class="severity severity-{severity_class}">{severity}</span><span class="status status-{status_class}">{status_label}</span></div>
  </div>
  <div class="facts">
    <span><b>{cwe}</b></span><span><b>类型</b> {kind}</span><span><b>置信度</b> {confidence}</span><span><b>位置</b> {location}</span>
  </div>
  <p>{description}</p>
  <div class="two-col">
    <section><h4>独立复核</h4><p>{note}</p><p><b>依据：</b>{rationale}</p><p><b>复核置信度：</b>{verification_confidence}</p></section>
    <section><h4>修复建议</h4><p><b>{priority}</b></p><div>{guidance}</div><p class="muted">{disclaimer}</p></section>
  </div>
  <details><summary>关联证据（{evidence_count}）</summary>{evidence_html}</details>
</article>
""".format(
                index=index,
                title=_escape(finding.get("title")),
                severity_class=_escape(str(severity.get("label") or "unknown").casefold()),
                severity=_escape(severity.get("label") or finding.get("severity") or "UNKNOWN"),
                status_class=_escape(status.casefold()),
                status_label=_escape(status_label),
                cwe=_escape(finding.get("cwe_id")),
                kind=_escape(finding.get("vulnerability_type")),
                confidence=_escape(finding.get("confidence")),
                location=_escape(location_text),
                description=_escape(finding.get("description")),
                note=_escape(reasoning.get("note")),
                rationale=_escape(verification.get("rationale") or reasoning.get("rationale")),
                verification_confidence=_escape(
                    verification.get("confidence") or reasoning.get("confidence")
                ),
                priority=_escape(remediation.get("priority_label")),
                guidance=_guidance(remediation.get("guidance")),
                disclaimer=_escape(remediation.get("disclaimer")),
                evidence_count=len(evidence_rows),
                evidence_html=evidence_html,
            )
        )
    return "".join(cards)


def _timeline_rows(rows: list[Any]) -> str:
    body = []
    for raw in rows:
        item = _mapping(raw)
        body.append(
            "<tr><td>{time}</td><td><code>{id}</code></td><td>{kind}</td>"
            "<td>{source}</td><td>{description}</td></tr>".format(
                time=_escape(item.get("timestamp")),
                id=_escape(item.get("evidence_id")),
                kind=_escape(item.get("evidence_type")),
                source=_escape(item.get("source")),
                description=_escape(item.get("description")),
            )
        )
    return "".join(body) or '<tr><td colspan="5" class="empty">无 Evidence 时间线。</td></tr>'


def render_report_html(
    report: Mapping[str, Any],
    *,
    title: str = "VulnAgent 漏洞分析报告",
) -> str:
    """Render a self-contained HTML report without changing public schemas."""

    task = _mapping(report.get("task"))
    target = _mapping(task.get("target"))
    summary = _mapping(report.get("summary"))
    risk = _mapping(report.get("risk_summary"))
    counts = _mapping(risk.get("counts"))
    limitations = _mapping(report.get("limitations"))
    missing = _list(limitations.get("missing_evidence_ids"))
    unverified = _list(limitations.get("unverified_finding_ids"))
    mock_notice = (
        '<div class="notice">此报告来自 Mock 输入，仅用于架构测试。</div>'
        if report.get("mock")
        else ""
    )
    limitations_html = "".join(
        (
            '<li>缺失 Evidence ID：{}</li>'.format(
                ", ".join(f"<code>{_escape(item)}</code>" for item in missing)
            )
            if missing
            else "<li>没有缺失的 Evidence ID。</li>",
            '<li>尚未独立复核的 Finding：{}</li>'.format(
                ", ".join(f"<code>{_escape(item)}</code>" for item in unverified)
            )
            if unverified
            else "<li>没有未复核 Finding。</li>",
            "<li>本报告是结构化事实的展示层，不等同于漏洞可利用性证明。</li>",
        )
    )
    return """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>{title}</title><style>
:root{{--ink:#172033;--muted:#657189;--line:#dce3ef;--bg:#f4f7fb;--brand:#3157d5;--card:#fff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 "Segoe UI","Microsoft YaHei",sans-serif}}
.wrap{{max-width:1120px;margin:0 auto;padding:32px 22px 56px}}header{{background:linear-gradient(135deg,#172554,#3157d5);color:#fff;padding:28px;border-radius:18px;box-shadow:0 12px 35px #1d3b8b26}}
h1{{margin:0 0 8px;font-size:28px}}h2{{font-size:19px;margin:30px 0 12px}}h3{{display:inline;font-size:17px}}h4{{margin:0 0 7px}}p{{margin:8px 0}}.subtitle{{opacity:.82}}.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:18px}}
.metric,.panel,.finding{{background:var(--card);border:1px solid var(--line);border-radius:14px}}.metric{{padding:14px}}.metric b{{display:block;font-size:24px;color:#183b9a}}.metric span,.muted{{color:var(--muted);font-size:12px}}
.panel{{padding:18px;margin:12px 0}}.finding{{padding:20px;margin:12px 0}}.finding-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}}.index{{color:var(--brand);font-weight:700;margin-right:8px}}
.badges{{display:flex;gap:7px}}.severity,.status{{border-radius:999px;padding:3px 9px;font-size:12px;font-weight:700}}.severity-critical{{background:#fee2e2;color:#991b1b}}.severity-high{{background:#ffedd5;color:#9a3412}}.severity-medium{{background:#fef3c7;color:#92400e}}.severity-low,.severity-info,.severity-unknown{{background:#e8eef8;color:#385070}}
.status-confirmed{{background:#dcfce7;color:#166534}}.status-rejected{{background:#e5e7eb;color:#374151}}.status-uncertain,.status-candidate,.status-verifying{{background:#e0e7ff;color:#3730a3}}
.facts{{display:flex;flex-wrap:wrap;gap:8px 18px;margin:13px 0;color:#475569}}.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:14px 0}}.two-col section{{background:#f8fafc;border-radius:10px;padding:13px}}
table{{width:100%;border-collapse:collapse;margin-top:10px;font-size:12px}}th,td{{border-bottom:1px solid #e8edf5;padding:8px;text-align:left;vertical-align:top}}th{{color:#526078;background:#f8fafc}}code{{overflow-wrap:anywhere;color:#2648a8}}details{{margin-top:12px}}summary{{cursor:pointer;font-weight:650;color:#2848a2}}.notice{{margin:12px 0;padding:12px;background:#fff4ce;border:1px solid #f2d16b;border-radius:10px}}.empty{{color:var(--muted);padding:12px}}ul{{margin:7px 0;padding-left:22px}}.guidance{{margin:7px 0;padding-left:20px}}
@media(max-width:760px){{.grid{{grid-template-columns:repeat(2,1fr)}}.two-col{{grid-template-columns:1fr}}.finding-head{{display:block}}.badges{{margin-top:8px}}}}
@media print{{body{{background:#fff}}.wrap{{max-width:none;padding:0}}header,.metric,.panel,.finding{{box-shadow:none;break-inside:avoid}}details{{display:block}}}}
</style></head><body><main class="wrap">
<header><h1>{title}</h1><div class="subtitle">Task {task_id} · Target {target_id} · {target_type} · 状态 {task_status}</div></header>
{mock_notice}
<section class="grid">
<div class="metric"><b>{finding_count}</b><span>Findings</span></div><div class="metric"><b>{evidence_count}</b><span>Evidence</span></div><div class="metric"><b>{confirmed}</b><span>Confirmed</span></div><div class="metric"><b>{rejected}</b><span>Rejected</span></div><div class="metric"><b>{overall}</b><span>最高风险</span></div>
</section>
<section class="panel"><h2>任务与风险摘要</h2><p>{headline}</p><p><b>目标路径：</b><code>{target_path}</code></p><p><b>创建时间：</b>{created_at}</p></section>
<h2>漏洞发现与独立复核</h2>{finding_cards}
<section class="panel"><h2>Evidence 时间线</h2><table><thead><tr><th>时间</th><th>Evidence ID</th><th>类型</th><th>来源</th><th>说明</th></tr></thead><tbody>{timeline}</tbody></table></section>
<section class="panel"><h2>限制与完整性检查</h2><ul>{limitations}</ul></section>
</main></body></html>""".format(
        title=_escape(title),
        task_id=_escape(task.get("task_id")),
        target_id=_escape(target.get("target_id")),
        target_type=_escape(target.get("target_type")),
        task_status=_escape(task.get("status")),
        mock_notice=mock_notice,
        finding_count=_escape(summary.get("finding_count", 0)),
        evidence_count=_escape(summary.get("evidence_count", 0)),
        confirmed=_escape(counts.get("confirmed", 0)),
        rejected=_escape(counts.get("rejected", 0)),
        overall=_escape(risk.get("overall_level") or "NONE"),
        headline=_escape(risk.get("headline")),
        target_path=_escape(_display_path(target.get("path"))),
        created_at=_escape(task.get("created_at")),
        finding_cards=_finding_cards(_list(report.get("findings"))),
        timeline=_timeline_rows(_list(report.get("evidence_timeline"))),
        limitations=limitations_html,
    )


def write_report_html(
    report: Mapping[str, Any],
    output_path: Path,
    *,
    title: str = "VulnAgent 漏洞分析报告",
) -> Path:
    """Atomically write a self-contained UTF-8 report and return its path."""

    destination = output_path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(render_report_html(report, title=title), encoding="utf-8")
    temporary.replace(destination)
    return destination
