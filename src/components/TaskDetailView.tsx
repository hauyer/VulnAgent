import React from "react";
import {
  CheckCircle2,
  Clock,
  Shield,
  FileText,
  Activity,
  ChevronRight,
  Database,
  ArrowRight,
  Sparkles,
} from "lucide-react";
import { Task, DomainEvent, VulnerabilityCandidate, Evidence } from "../types.js";

interface TaskDetailViewProps {
  task: Task;
  events: DomainEvent[];
  findings: VulnerabilityCandidate[];
  evidence: Evidence[];
  onOpenReport: () => void;
  onOpenEvidence: (evidenceItem?: Evidence) => void;
  onSelectFinding: (finding: VulnerabilityCandidate) => void;
}

const LIFECYCLE_STAGES = [
  { key: "planning", label: "Planner Agent" },
  { key: "analyzing", label: "Source/Binary Audit" },
  { key: "dynamic_testing", label: "Fuzz Engine" },
  { key: "verifying", label: "Verification Agent" },
  { key: "reporting", label: "Report Agent" },
];

export const TaskDetailView: React.FC<TaskDetailViewProps> = ({
  task,
  events,
  findings,
  evidence,
  onOpenReport,
  onOpenEvidence,
  onSelectFinding,
}) => {
  const confirmedCount = findings.filter((f) => f.status === "confirmed").length;
  const uncertainCount = findings.filter((f) => f.status === "uncertain").length;

  return (
    <div className="space-y-5">
      {/* Top Banner & Status Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-xs text-slate-400 font-semibold">{task.task_id}</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold border ${
                  task.status === "completed"
                    ? "bg-emerald-950/60 border-emerald-700 text-emerald-300"
                    : task.status === "failed"
                    ? "bg-rose-950/60 border-rose-700 text-rose-300"
                    : "bg-cyan-950/60 border-cyan-700 text-cyan-300 animate-pulse"
                }`}
              >
                {task.status}
              </span>
            </div>
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <span className="font-mono text-cyan-400">{task.target.path}</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Target Type: <span className="text-slate-200 capitalize font-medium">{task.target.target_type}</span>{" "}
              {task.target.language && (
                <>
                  &bull; Language: <span className="text-slate-200 font-medium">{task.target.language}</span>
                </>
              )}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => onOpenEvidence()}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 hover:border-slate-600 text-xs font-medium text-slate-200 transition-colors cursor-pointer"
            >
              <Database className="w-3.5 h-3.5 text-cyan-400" />
              <span>Evidence Artifacts ({evidence.length})</span>
            </button>

            <button
              onClick={onOpenReport}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors cursor-pointer shadow-md shadow-cyan-950"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Audit Report</span>
            </button>
          </div>
        </div>

        {/* Multi-Agent Pipeline Progress */}
        <div className="mt-5 pt-5 border-t border-slate-800/80">
          <div className="text-xs font-semibold text-slate-400 mb-3 flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              Multi-Agent Pipeline Progression
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              {task.status === "completed" ? "100% Complete" : "Executing..."}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            {LIFECYCLE_STAGES.map((stage, idx) => {
              const isCompleted = task.status === "completed";
              return (
                <div
                  key={stage.key}
                  className={`p-2.5 rounded-lg border text-center relative ${
                    isCompleted
                      ? "bg-slate-950/80 border-cyan-800/50 text-cyan-200"
                      : "bg-slate-950/40 border-slate-800 text-slate-400"
                  }`}
                >
                  <div className="flex items-center justify-center gap-1 text-[11px] font-semibold">
                    <span className="w-4 h-4 rounded-full bg-cyan-500/20 text-cyan-400 text-[10px] flex items-center justify-center font-mono">
                      {idx + 1}
                    </span>
                    <span>{stage.label}</span>
                  </div>
                  <div className="text-[10px] text-slate-400 mt-1 flex items-center justify-center gap-1">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    <span>Verified</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5">
          <span className="text-xs text-slate-400 block">Total Candidates</span>
          <span className="text-2xl font-bold font-mono text-slate-100">{findings.length}</span>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5">
          <span className="text-xs text-rose-400 block font-medium">Confirmed Vulnerabilities</span>
          <span className="text-2xl font-bold font-mono text-rose-400">{confirmedCount}</span>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5">
          <span className="text-xs text-amber-400 block font-medium">Uncertain / Review Queued</span>
          <span className="text-2xl font-bold font-mono text-amber-400">{uncertainCount}</span>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5">
          <span className="text-xs text-cyan-400 block font-medium">Evidence Chain Artifacts</span>
          <span className="text-2xl font-bold font-mono text-cyan-400">{evidence.length}</span>
        </div>
      </div>

      {/* Findings List & Real-time Trace Events */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Findings List */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
            <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Vulnerability Findings ({findings.length})
            </h4>
            <span className="text-[11px] text-slate-400">Click finding to inspect evidence</span>
          </div>

          {findings.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-xs">
              No vulnerabilities detected for this target.
            </div>
          ) : (
            <div className="space-y-2.5">
              {findings.map((f) => (
                <div
                  key={f.vulnerability_id}
                  onClick={() => onSelectFinding(f)}
                  className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-cyan-500/50 transition-all cursor-pointer group"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        {f.cwe_id && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
                            {f.cwe_id}
                          </span>
                        )}
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border ${
                            f.severity === "CRITICAL"
                              ? "bg-rose-950 text-rose-300 border-rose-800"
                              : f.severity === "HIGH"
                              ? "bg-amber-950 text-amber-300 border-amber-800"
                              : "bg-blue-950 text-blue-300 border-blue-800"
                          }`}
                        >
                          {f.severity || "MEDIUM"}
                        </span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                            f.status === "confirmed"
                              ? "bg-emerald-950/80 text-emerald-300 border-emerald-800"
                              : "bg-slate-800 text-slate-300 border-slate-700"
                          }`}
                        >
                          {f.status}
                        </span>
                      </div>
                      <h5 className="text-xs font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors">
                        {f.title}
                      </h5>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-0.5 shrink-0" />
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-2 mt-1.5">{f.description}</p>

                  <div className="flex items-center justify-between mt-2.5 pt-2 border-t border-slate-800/60 text-[11px] text-slate-400 font-mono">
                    <span>
                      Confidence:{" "}
                      <span className="text-slate-200 font-bold">{(f.confidence * 100).toFixed(0)}%</span>
                    </span>
                    <span>{f.evidence_ids.length} Evidence Artifacts</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Real-time Domain Event Trace */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg flex flex-col h-[480px]">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
            <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Multi-Agent Trace ({events.length})
            </h4>
            <span className="text-[11px] font-mono text-cyan-400">Deterministic Audit Trail</span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 pr-1 font-mono text-xs">
            {events.map((ev, i) => (
              <div
                key={ev.event_id || i}
                className="p-2.5 rounded bg-slate-950/70 border border-slate-800/80 text-slate-300"
              >
                <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
                  <span className="text-cyan-400 font-semibold uppercase">{ev.event_type}</span>
                  <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="text-[11px] text-slate-300 truncate">
                  {ev.payload.route && (
                    <span className="text-amber-300 mr-1.5">[{ev.payload.route}]</span>
                  )}
                  {ev.payload.description ||
                    ev.payload.title ||
                    ev.payload.plan ||
                    JSON.stringify(ev.payload)}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
