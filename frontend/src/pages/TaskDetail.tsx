import { useCallback, useEffect, useState } from "react";
import {
  getEvidence,
  getFindings,
  getReviews,
  getTask,
  getTrace,
  getVerifications,
  submitReview,
} from "../api";
import type { Evidence, Finding, Task, TraceEvent, Verification } from "../types";
import { statusStyle } from "../types";

type Tab = "trace" | "findings" | "evidence" | "verification" | "report";

export default function TaskDetail({
  taskId,
  onBack,
}: {
  taskId: string;
  onBack: () => void;
}) {
  const [tab, setTab] = useState<Tab>("trace");
  const [task, setTask] = useState<Task | null>(null);
  const [trace, setTrace] = useState<TraceEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [verifications, setVerifications] = useState<Verification[]>([]);
  const [reviews, setReviews] = useState<unknown[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getTask(taskId).then(setTask).catch((e: unknown) => setError(String(e)));
    getTrace(taskId).then(setTrace).catch(() => undefined);
    getFindings(taskId).then(setFindings).catch(() => undefined);
    getEvidence(taskId).then(setEvidence).catch(() => undefined);
    getVerifications(taskId).then(setVerifications).catch(() => undefined);
    getReviews(taskId).then(setReviews).catch(() => undefined);
  }, [taskId]);

  useEffect(load, [load]);

  const style = task ? statusStyle(task.status) : null;

  return (
    <div className="space-y-4">
      <button className="text-sm text-slate-500 hover:text-slate-800" onClick={onBack}>
        ← 返回任务列表
      </button>

      {task && (
        <section className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="font-mono text-sm font-semibold">{task.task_id}</h2>
            {style && (
              <span className={`rounded-full px-2 py-0.5 text-xs ${style.cls}`}>
                {style.label}
              </span>
            )}
            <span className="text-xs text-slate-500">{task.target.path}</span>
          </div>
          {task.error && (
            <p className="mt-2 rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
              错误：{task.error}
            </p>
          )}
        </section>
      )}
      {error && <p className="text-sm text-red-600">{error}</p>}

      <nav className="flex gap-1 border-b border-slate-200">
        {(
          [
            ["trace", "Trace"],
            ["findings", "候选"],
            ["evidence", "证据"],
            ["verification", "复核"],
            ["report", "报告"],
          ] as [Tab, string][]
        ).map(([key, label]) => (
          <button
            key={key}
            className={`rounded-t-md px-3 py-2 text-sm ${
              tab === key
                ? "border border-b-0 border-slate-200 bg-white font-medium text-slate-800"
                : "text-slate-500 hover:text-slate-800"
            }`}
            onClick={() => setTab(key)}
          >
            {label}
          </button>
        ))}
      </nav>

      {tab === "trace" && <TracePanel events={trace} />}
      {tab === "findings" && (
        <FindingsPanel taskId={taskId} findings={findings} reviews={reviews} onReview={load} />
      )}
      {tab === "evidence" && <EvidencePanel items={evidence} />}
      {tab === "verification" && <VerificationPanel items={verifications} />}
      {tab === "report" && <ReportPanel taskId={taskId} />}
    </div>
  );
}

function TracePanel({ events }: { events: TraceEvent[] }) {
  if (events.length === 0) {
    return <p className="py-6 text-center text-sm text-slate-400">暂无轨迹事件</p>;
  }
  return (
    <ol className="space-y-2">
      {events.map((event, index) => (
        <li key={index} className="flex gap-3 rounded-md border border-slate-100 bg-white p-3 text-sm">
          <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full bg-slate-400" />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs font-semibold">{event.event_type}</span>
              <span className="text-xs text-slate-400">{event.producer}</span>
              <span className="text-xs text-slate-400">
                {new Date(event.timestamp).toLocaleTimeString()}
              </span>
            </div>
            <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-slate-600">
              {JSON.stringify(event.payload, null, 2)}
            </pre>
          </div>
        </li>
      ))}
    </ol>
  );
}

function FindingsPanel({
  taskId,
  findings,
  reviews,
  onReview,
}: {
  taskId: string;
  findings: Finding[];
  reviews: unknown[];
  onReview: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);

  const review = async (vulnerabilityId: string, decision: "accepted" | "rejected") => {
    setBusy(vulnerabilityId);
    try {
      await submitReview(taskId, vulnerabilityId, {
        decision,
        note: decision === "accepted" ? "人工复核接受" : "人工复核拒绝",
      });
      onReview();
    } catch {
      // surface through the page-level error next refresh
    } finally {
      setBusy(null);
    }
  };

  if (findings.length === 0) {
    return <p className="py-6 text-center text-sm text-slate-400">暂无候选</p>;
  }
  return (
    <div className="space-y-3">
      {findings.map((finding) => (
        <div key={finding.vulnerability_id} className="rounded-lg border border-slate-200 bg-white p-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-semibold text-slate-800">{finding.title}</span>
            <span className="rounded-full bg-orange-100 px-2 py-0.5 text-xs text-orange-700">
              {finding.cwe_id || "无 CWE"}
            </span>
            <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600">
              {finding.source_agent}
            </span>
            <span className="text-xs text-slate-500">
              置信度 {(finding.confidence * 100).toFixed(0)}%
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-600">{finding.description}</p>
          <p className="mt-1 font-mono text-xs text-slate-500">
            {typeof finding.location === "string"
              ? finding.location
              : `${finding.location.file_path}:${finding.location.line_start}`}
          </p>
          <div className="mt-2 flex gap-2">
            <button
              className="rounded-md bg-green-600 px-2 py-1 text-xs text-white disabled:opacity-50"
              onClick={() => review(finding.vulnerability_id, "accepted")}
              disabled={busy === finding.vulnerability_id}
            >
              复核接受
            </button>
            <button
              className="rounded-md bg-red-600 px-2 py-1 text-xs text-white disabled:opacity-50"
              onClick={() => review(finding.vulnerability_id, "rejected")}
              disabled={busy === finding.vulnerability_id}
            >
              复核拒绝
            </button>
          </div>
        </div>
      ))}
      {reviews.length > 0 && (
        <p className="text-xs text-slate-500">人工标注记录 {reviews.length} 条</p>
      )}
    </div>
  );
}

function EvidencePanel({ items }: { items: Evidence[] }) {
  if (items.length === 0) {
    return <p className="py-6 text-center text-sm text-slate-400">暂无证据</p>;
  }
  return (
    <div className="space-y-2">
      {items.map((item) => (
        <div key={item.evidence_id} className="rounded-lg border border-slate-200 bg-white p-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full bg-violet-100 px-2 py-0.5 text-xs text-violet-700">
              {item.evidence_type}
            </span>
            <span className="text-xs text-slate-500">{item.source}</span>
          </div>
          <p className="mt-1 text-slate-600">{item.description}</p>
          {item.artifact_path && (
            <p className="mt-1 font-mono text-xs text-slate-400">{item.artifact_path}</p>
          )}
          {Object.keys(item.data).length > 0 && (
            <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-slate-500">
              {JSON.stringify(item.data, null, 2)}
            </pre>
          )}
        </div>
      ))}
    </div>
  );
}

function VerificationPanel({ items }: { items: Verification[] }) {
  const badge = (status: string) => {
    if (status === "CONFIRMED") return "bg-green-100 text-green-700";
    if (status === "REJECTED") return "bg-red-100 text-red-700";
    if (status === "UNCERTAIN") return "bg-amber-100 text-amber-700";
    return "bg-gray-100 text-gray-600";
  };
  if (items.length === 0) {
    return <p className="py-6 text-center text-sm text-slate-400">暂无复核记录</p>;
  }
  return (
    <div className="space-y-2">
      {items.map((item) => (
        <div key={item.vulnerability_id} className="flex items-center gap-3 rounded-lg border border-slate-200 bg-white p-3 text-sm">
          <span className={`rounded-full px-2 py-0.5 text-xs ${badge(item.status)}`}>
            {item.status}
          </span>
          <span className="font-mono text-xs">{item.vulnerability_id}</span>
          <span className="text-xs text-slate-500">置信度 {(item.confidence * 100).toFixed(0)}%</span>
        </div>
      ))}
    </div>
  );
}

function ReportPanel({ taskId }: { taskId: string }) {
  return (
    <div className="space-y-3 rounded-lg border border-slate-200 bg-white p-4">
      <p className="text-sm text-slate-600">
        报告由 Report Agent 生成，含证据链与合规声明（仅用于安全审计与防御研究）。
      </p>
      <div className="flex gap-2">
        <a
          className="rounded-md bg-slate-800 px-3 py-1.5 text-sm text-white"
          href={`/api/tasks/${taskId}/report.html`}
          target="_blank"
          rel="noreferrer"
        >
          打开 HTML 报告
        </a>
        <a
          className="rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-700"
          href={`/api/tasks/${taskId}/report.pdf`}
          target="_blank"
          rel="noreferrer"
        >
          下载 PDF
        </a>
      </div>
    </div>
  );
}
