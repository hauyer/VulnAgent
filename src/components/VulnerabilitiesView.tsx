import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  Code,
  FileCode,
  Lightbulb,
  Layers,
  Sparkles,
  Info,
  Check,
} from "lucide-react";
import { VulnerabilityCandidate, Evidence, VulnerabilityStatus } from "../types.js";
import { useTranslation } from "../i18n.js";

interface VulnerabilitiesViewProps {
  findings: VulnerabilityCandidate[];
  evidenceList: Evidence[];
  onInspectEvidence: (evidenceId: string) => void;
}

export const VulnerabilitiesView: React.FC<VulnerabilitiesViewProps> = ({
  findings,
  evidenceList,
  onInspectEvidence,
}) => {
  const { t, language } = useTranslation();
  const [selectedStatus, setSelectedStatus] = useState<string>("all");
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityCandidate | null>(
    findings[0] || null
  );

  React.useEffect(() => {
    if (!selectedFinding && findings.length > 0) {
      setSelectedFinding(findings[0]);
    }
  }, [findings, selectedFinding]);

  const filtered = findings.filter((f) => {
    if (selectedStatus === "all") return true;
    return f.status === selectedStatus;
  });

  const confirmedCount = findings.filter((f) => f.status === "confirmed").length;
  const uncertainCount = findings.filter((f) => f.status === "uncertain").length;
  const selectedEvidence = selectedFinding
    ? evidenceList.filter((item) => selectedFinding.evidence_ids.includes(item.evidence_id))
    : [];
  const selectedEvidenceTypes = Array.from(
    new Set(selectedEvidence.map((item) => item.evidence_type.replaceAll("_", " "))),
  ).join(", ");
  const hasVerificationEvidence = selectedEvidence.some(
    (item) => item.evidence_type === "verification_result",
  );

  const getSeverityBadge = (severity?: string | null) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-[#fce8e6] text-[#dc322f] border-[#f5b8b5]";
      case "HIGH":
        return "bg-[#fbf4e6] text-[#b58900] border-[#ecd8a6]";
      case "MEDIUM":
        return "bg-[#eef4fb] text-[#268bd2] border-[#b9d6f3]";
      case "LOW":
        return "bg-[#eee8d5] text-[#586e75] border-[#dfd6bf]";
      default:
        return "bg-[#eee8d5] text-[#586e75] border-[#dfd6bf]";
    }
  };

  const getStatusBadge = (status: VulnerabilityStatus) => {
    switch (status) {
      case "confirmed":
        return "bg-[#edf5d3] text-[#859900] border-[#cce38d]";
      case "uncertain":
        return "bg-[#fbf4e6] text-[#b58900] border-[#ecd8a6]";
      case "verifying":
        return "bg-[#eef7f6] text-[#2aa198] border-[#bfe3e0] animate-pulse";
      case "rejected":
        return "bg-[#fce8e6] text-[#dc322f] border-[#f5b8b5]";
      default:
        return "bg-[#eee8d5] text-[#586e75] border-[#dfd6bf]";
    }
  };

  const getStatusLabel = (st: string) => {
    if (language === "zh") {
      switch (st) {
        case "all": return "全部";
        case "confirmed": return "已确认";
        case "uncertain": return "存疑待查";
        case "candidate": return "候选";
        case "verifying": return "复核中";
        case "rejected": return "误报剔除";
        default: return st;
      }
    }
    return st.toUpperCase();
  };

  return (
    <div className="space-y-6">
      {/* Top Protocol Header Banner */}
      <div className="p-5 rounded-2xl bg-[#f4eedb] border border-[#dfd6bf] shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-6 h-6 rounded-lg bg-[#2aa198]/10 border border-[#2aa198]/30 flex items-center justify-center text-[#2aa198]">
              <ShieldCheck className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-base font-bold text-[#2b3638]">{t("vulnTitle")}</h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#edf5d3] text-[#859900] border border-[#cce38d] font-semibold">
              AGENTS.md Decoupled Architecture
            </span>
          </div>
          <p className="text-xs text-[#586e75]">
            {t("vulnSubtitle")}
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <div className="px-3 py-1.5 rounded-lg bg-[#fce8e6] border border-[#f5b8b5] text-[#dc322f]">
            <span className="font-bold">{confirmedCount}</span> {language === "zh" ? "项独立复核确认" : "Confirmed"}
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-[#fbf4e6] border border-[#ecd8a6] text-[#b58900]">
            <span className="font-bold">{uncertainCount}</span> {language === "zh" ? "复核队列中" : "Review Queued"}
          </div>
        </div>
      </div>

      {/* Main Grid: Finding Cards + Dossier Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left List */}
        <div className="lg:col-span-5 space-y-3">
          {/* Status Filter Tabs */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
            {["all", "confirmed", "uncertain", "candidate"].map((st) => (
              <button
                key={st}
                onClick={() => setSelectedStatus(st)}
                className={`px-3 py-1.5 rounded-lg font-mono text-xs whitespace-nowrap transition-colors cursor-pointer ${
                  selectedStatus === st
                    ? "bg-[#eef7f6] text-[#2aa198] border border-[#2aa198] font-bold"
                    : "bg-[#eee8d5] text-[#586e75] hover:bg-[#e6deca] hover:text-[#2b3638]"
                }`}
              >
                {getStatusLabel(st)} ({findings.filter((f) => st === "all" || f.status === st).length})
              </button>
            ))}
          </div>

          <div className="space-y-2.5 max-h-[640px] overflow-y-auto pr-1">
            {filtered.length === 0 ? (
              <div className="p-12 text-center text-[#839496] text-xs">
                {language === "zh" ? "该筛选分类下暂无漏洞卷宗记录" : "No vulnerabilities in this filter category."}
              </div>
            ) : (
              filtered.map((f) => {
                const isSelected = selectedFinding?.vulnerability_id === f.vulnerability_id;
                return (
                  <div
                    key={f.vulnerability_id}
                    onClick={() => setSelectedFinding(f)}
                    className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                      isSelected
                        ? "bg-[#eef7f6] border-[#2aa198] shadow-sm ring-1 ring-[#2aa198]/30"
                        : "bg-[#fdfaf3] border-[#dfd6bf] hover:border-[#cbbea2] hover:bg-[#fcf8ed]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-2 flex-wrap">
                      <div className="flex items-center gap-1.5">
                        {f.cwe_id && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#eee8d5] text-[#2aa198] border border-[#dfd6bf]">
                            {f.cwe_id}
                          </span>
                        )}
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getSeverityBadge(f.severity)}`}>
                          {f.severity || "MEDIUM"}
                        </span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getStatusBadge(f.status)}`}>
                        {getStatusLabel(f.status)}
                      </span>
                    </div>

                    <h4 className="text-xs font-bold text-[#2b3638] line-clamp-1">
                      {f.title}
                    </h4>

                    <p className="text-xs text-[#586e75] line-clamp-2 mt-1 leading-relaxed">
                      {f.description}
                    </p>

                    <div className="flex items-center justify-between text-[11px] text-[#839496] mt-3 pt-2 border-t border-[#dfd6bf] font-mono">
                      <span>{t("vulnConfidence")}: <strong className="text-[#2b3638]">{(f.confidence * 100).toFixed(0)}%</strong></span>
                      <span className="text-[#2aa198] font-semibold">{f.evidence_ids.length} {language === "zh" ? "条证据记录" : "Evidence Records"}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Dossier Detail */}
        <div className="lg:col-span-7 space-y-4">
          {selectedFinding ? (
            <div className="p-6 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm space-y-5">
              {/* Header */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 border-b border-[#dfd6bf] pb-4">
                <div>
                  <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                    {selectedFinding.cwe_id && (
                      <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-[#eee8d5] text-[#2aa198] border border-[#dfd6bf]">
                        {selectedFinding.cwe_id}
                      </span>
                    )}
                    <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase border ${getSeverityBadge(selectedFinding.severity)}`}>
                      {selectedFinding.severity || "MEDIUM"}
                    </span>
                    <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase border ${getStatusBadge(selectedFinding.status)}`}>
                      {getStatusLabel(selectedFinding.status)}
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-[#2b3638]">{selectedFinding.title}</h3>
                  <span className="text-xs font-mono text-[#586e75] mt-1 block">
                    ID: {selectedFinding.vulnerability_id}
                  </span>
                </div>

                {selectedFinding.metadata?.cvss_score && (
                  <div className="p-3 rounded-xl bg-[#f5eed9] border border-[#dfd6bf] text-center sm:text-right">
                    <span className="text-[10px] text-[#586e75] uppercase font-mono block">CVSS v3.1 Score</span>
                    <span className="text-2xl font-bold font-mono text-[#dc322f]">
                      {selectedFinding.metadata.cvss_score}
                    </span>
                  </div>
                )}
              </div>

              {/* Description */}
              <div>
                <span className="text-xs font-semibold text-[#2b3638] block mb-1.5">
                  {language === "zh" ? "漏洞描述与危害机理" : "Vulnerability Summary & Impact"}
                </span>
                <p className="text-xs text-[#586e75] leading-relaxed bg-[#f5eed9] p-4 rounded-xl border border-[#dfd6bf]">
                  {selectedFinding.description}
                </p>
              </div>

              {/* Code Location */}
              {selectedFinding.location && (
                <div className="p-3.5 rounded-xl bg-[#f5eed9] border border-[#dfd6bf] flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-[#2aa198]" />
                    <span className="text-[#586e75]">{language === "zh" ? "目标代码位置:" : "Target Location:"}</span>
                    <span className="text-[#2b3638] font-medium">
                      {selectedFinding.location.file_path || selectedFinding.location.binary_address}
                      {selectedFinding.location.line_start && `:${selectedFinding.location.line_start}`}
                    </span>
                  </div>
                  {selectedFinding.location.function_name && (
                    <span className="text-[#2aa198] font-medium">
                      fn {selectedFinding.location.function_name}()
                    </span>
                  )}
                </div>
              )}

              {/* Multi-Agent Verification Timeline */}
              <div className="p-4 rounded-xl bg-[#f5eed9] border border-[#dfd6bf] space-y-3">
                <span className="text-xs font-semibold text-[#2aa198] uppercase tracking-wider flex items-center gap-2">
                  <Layers className="w-4 h-4" />
                  {t("vulnVerificationDossier")}
                </span>
                
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 font-mono text-xs">
                  <div className="p-2.5 rounded-lg bg-[#fdfaf3] border border-[#dfd6bf]">
                    <span className="text-[10px] text-[#839496] uppercase block">
                      {language === "zh" ? "1. 发现提报智能体" : "1. Detection Agent"}
                    </span>
                    <span className="text-[#2aa198] font-medium">{selectedFinding.source_agent}</span>
                    <span className="text-[10px] text-[#586e75] block mt-0.5">Status: CANDIDATE</span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-[#fdfaf3] border border-[#dfd6bf]">
                    <span className="text-[10px] text-[#839496] uppercase block">
                      {language === "zh" ? "2. 关联结构化证据" : "2. Linked Structured Evidence"}
                    </span>
                    <span className="text-[#b58900] font-medium">
                      {selectedEvidence.length} {language === "zh" ? "项证据" : "evidence items"}
                    </span>
                    <span className="text-[10px] text-[#586e75] block mt-0.5">
                      {selectedEvidenceTypes || (language === "zh" ? "暂无关联证据" : "No linked evidence")}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-[#fdfaf3] border border-[#cce38d]">
                    <span className="text-[10px] text-[#859900] uppercase block">
                      {language === "zh" ? "3. 独立唯一确认裁定" : "3. Sole Confirmer"}
                    </span>
                    <span className="text-[#859900] font-bold">
                      {hasVerificationEvidence
                        ? "VerificationAgent"
                        : language === "zh"
                          ? "未找到复核证据"
                          : "No verification evidence"}
                    </span>
                    <span className="text-[10px] text-[#859900] block mt-0.5 font-bold">
                      Status: {selectedFinding.status.toUpperCase()}
                    </span>
                  </div>
                </div>

                <p className="text-[11px] text-[#586e75] leading-relaxed pt-1">
                  {t("vulnVerificationNote")}
                </p>
              </div>

              {/* Linked Evidence Artifacts */}
              <div>
                <span className="text-xs font-semibold text-[#2b3638] block mb-2">
                  {t("vulnEvidenceRef")} ({selectedFinding.evidence_ids.length})
                </span>
                <div className="flex flex-wrap gap-2">
                  {selectedFinding.evidence_ids.map((evId) => {
                    const match = evidenceList.find((e) => e.evidence_id === evId);
                    return (
                      <button
                        key={evId}
                        onClick={() => onInspectEvidence(evId)}
                        className="px-3 py-2 rounded-lg bg-[#f5eed9] hover:bg-[#eee8d5] border border-[#dfd6bf] text-left transition-colors cursor-pointer group flex items-center gap-2 text-xs shadow-2xs"
                      >
                        <FileCode className="w-3.5 h-3.5 text-[#2aa198]" />
                        <div>
                          <span className="font-mono text-[11px] text-[#2aa198] font-bold block">
                            {evId}
                          </span>
                          <span className="text-[10px] text-[#586e75] line-clamp-1">
                            {match ? match.description : (language === "zh" ? "查看证据" : "View Evidence")}
                          </span>
                        </div>
                        <ArrowRight className="w-3 h-3 text-[#839496] group-hover:text-[#2aa198] transition-transform group-hover:translate-x-0.5" />
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-16 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] text-center text-[#839496] text-xs">
              {language === "zh" ? "请在左侧列表选择漏洞候选记录" : "Select a vulnerability candidate from the left list."}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
