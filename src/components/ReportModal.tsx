import React from "react";
import { X, FileText, Download, ShieldCheck, AlertTriangle, CheckCircle, Lightbulb } from "lucide-react";
import { ReportResult } from "../types.js";

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: ReportResult | null;
}

export const ReportModal: React.FC<ReportModalProps> = ({ isOpen, onClose, report }) => {
  if (!isOpen || !report) return null;

  const content = report.content || {};
  const metrics = content.metrics || {
    total_candidates: 0,
    confirmed_vulnerabilities: 0,
    rejected_false_positives: 0,
    uncertain_findings: 0,
    evidence_count: 0,
  };

  const handleDownload = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `vulnagent-report-${report.task_id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[88vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <FileText className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-100">Vulnerability Assessment Report</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                  {report.task_id}
                </span>
              </div>
              <p className="text-xs text-slate-400">Autonomous Multi-Agent Synthesis & Verification</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export JSON</span>
            </button>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 flex items-center justify-center text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Executive Summary */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800">
            <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-2 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" />
              Executive Summary
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              {content.executive_summary || content.summary || "Security audit completed successfully."}
            </p>
          </div>

          {/* Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] text-slate-400 block">Total Candidates</span>
              <span className="text-xl font-bold font-mono text-slate-200">{metrics.total_candidates}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] text-rose-400 block font-medium">Confirmed Vulnerabilities</span>
              <span className="text-xl font-bold font-mono text-rose-400">
                {metrics.confirmed_vulnerabilities}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] text-amber-400 block font-medium">Uncertain Findings</span>
              <span className="text-xl font-bold font-mono text-amber-400">
                {metrics.uncertain_findings}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-[11px] text-cyan-400 block font-medium">Evidence Artifacts</span>
              <span className="text-xl font-bold font-mono text-cyan-400">{metrics.evidence_count}</span>
            </div>
          </div>

          {/* Detailed Findings List */}
          {content.findings && content.findings.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">
                Assessed Vulnerabilities
              </h4>
              <div className="space-y-3">
                {content.findings.map((f: any, idx: number) => (
                  <div
                    key={f.vulnerability_id || idx}
                    className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2"
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2">
                        {f.cwe_id && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
                            {f.cwe_id}
                          </span>
                        )}
                        <span className="font-semibold text-xs text-slate-100">{f.title}</span>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold border ${
                          f.status === "confirmed"
                            ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                            : "bg-slate-800 text-slate-400 border-slate-700"
                        }`}
                      >
                        {f.status}
                      </span>
                    </div>

                    <p className="text-xs text-slate-400">{f.description}</p>

                    {f.location && (
                      <div className="text-[11px] font-mono text-slate-400 pt-1">
                        Location:{" "}
                        <span className="text-slate-300">
                          {f.location.file_path || f.location.module_name || f.location.binary_address}
                          {f.location.line_start && `:${f.location.line_start}`}
                        </span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation Recommendations */}
          {content.recommendations && content.recommendations.length > 0 && (
            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800">
              <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Lightbulb className="w-4 h-4" />
                Remediation Recommendations
              </h4>
              <ul className="space-y-2 text-xs text-slate-300">
                {content.recommendations.map((rec: string, i: number) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
