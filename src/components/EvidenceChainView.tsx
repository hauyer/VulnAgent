import React, { useState } from "react";
import {
  Database,
  FileCode,
  Bug,
  ShieldCheck,
  Terminal,
  Activity,
  Copy,
  Check,
  ExternalLink,
  Code,
  Cpu,
  Layers,
  Search,
  Filter,
} from "lucide-react";
import { Evidence, EvidenceType } from "../types.js";
import { useTranslation } from "../i18n.js";

interface EvidenceChainViewProps {
  evidenceList: Evidence[];
  initialSelectedId?: string;
}

export const EvidenceChainView: React.FC<EvidenceChainViewProps> = ({
  evidenceList,
  initialSelectedId,
}) => {
  const { t, language } = useTranslation();
  const [selected, setSelected] = useState<Evidence | null>(
    evidenceList.find((e) => e.evidence_id === initialSelectedId) || evidenceList[0] || null
  );
  const [filterType, setFilterType] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [copied, setCopied] = useState(false);

  React.useEffect(() => {
    if (initialSelectedId) {
      const match = evidenceList.find((e) => e.evidence_id === initialSelectedId);
      if (match) setSelected(match);
    } else if (!selected && evidenceList.length > 0) {
      setSelected(evidenceList[0]);
    }
  }, [initialSelectedId, evidenceList]);

  const filtered = evidenceList.filter((e) => {
    const matchesFilter = filterType === "all" || e.evidence_type === filterType;
    const matchesSearch =
      e.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.evidence_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.evidence_type.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const handleCopyJson = () => {
    if (!selected) return;
    navigator.clipboard.writeText(JSON.stringify(selected, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getBadgeColor = (type: EvidenceType) => {
    switch (type) {
      case "crash_log":
      case "stack_trace":
        return "bg-[#fce8e6] text-[#dc322f] border-[#f5b8b5]";
      case "sanitizer_output":
        return "bg-[#fbf4e6] text-[#b58900] border-[#ecd8a6]";
      case "verification_result":
        return "bg-[#edf5d3] text-[#859900] border-[#cce38d]";
      case "source_location":
      case "code_snippet":
      case "taint_path":
        return "bg-[#eef7f6] text-[#2aa198] border-[#bfe3e0]";
      case "disassembly":
      case "binary_address":
        return "bg-[#f4f1f9] text-[#6c71c4] border-[#d8d3ec]";
      default:
        return "bg-[#eee8d5] text-[#586e75] border-[#dfd6bf]";
    }
  };

  const getFilterLabel = (filter: string) => {
    if (language === "zh") {
      switch (filter) {
        case "all": return "全部凭据";
        case "source_location": return "源码位置";
        case "crash_log": return "崩溃日志";
        case "verification_result": return "复核结果";
        case "sanitizer_output": return "Sanitizer 诊断";
        default: return filter;
      }
    }
    return filter === "all" ? "All Artifacts" : filter.replace("_", " ");
  };

  const evidenceScore = (item: Evidence): number =>
    item.evidence_type === "verification_result" && typeof item.data?.confidence === "number"
      ? item.data.confidence
      : item.reliability;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-5 rounded-2xl bg-[#f4eedb] border border-[#dfd6bf] shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-6 h-6 rounded-lg bg-[#2aa198]/10 border border-[#2aa198]/30 flex items-center justify-center text-[#2aa198]">
              <Database className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-base font-bold text-[#2b3638]">{t("eviTitle")}</h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#e6deca] text-[#2aa198] border border-[#d2c8af] font-semibold">
              Evidence-First
            </span>
          </div>
          <p className="text-xs text-[#586e75]">
            {t("eviSubtitle")}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-3 py-1.5 rounded-lg bg-[#fdfaf3] border border-[#dfd6bf] text-xs font-mono text-[#586e75] shadow-2xs">
            <span className="text-[#2aa198] font-bold">{evidenceList.length}</span>{" "}
            {language === "zh" ? "条证据记录" : "evidence records"}
          </div>
        </div>
      </div>

      {/* Main Split: Artifact Selector + Deep Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Artifact List */}
        <div className="lg:col-span-5 space-y-3">
          {/* Filter and Search */}
          <div className="space-y-2">
            <div className="relative">
              <Search className="w-4 h-4 text-[#839496] absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={language === "zh" ? "搜索凭据 ID、污点路径、崩溃寄存器..." : "Search artifacts, taint paths, RIPs..."}
                className="w-full pl-9 pr-3 py-2 bg-[#fdfaf3] border border-[#dfd6bf] rounded-xl text-xs font-mono text-[#2b3638] placeholder:text-[#93a1a1] focus:outline-none focus:border-[#2aa198]"
              />
            </div>

            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
              {["all", "source_location", "crash_log", "verification_result", "sanitizer_output"].map(
                (filter) => (
                  <button
                    key={filter}
                    onClick={() => setFilterType(filter)}
                    className={`px-2.5 py-1 rounded-lg font-mono text-[11px] whitespace-nowrap transition-colors cursor-pointer capitalize ${
                      filterType === filter
                        ? "bg-[#eef7f6] text-[#2aa198] border border-[#2aa198] font-bold"
                        : "bg-[#eee8d5] text-[#586e75] hover:bg-[#e6deca] hover:text-[#2b3638]"
                    }`}
                  >
                    {getFilterLabel(filter)}
                  </button>
                )
              )}
            </div>
          </div>

          {/* List Items */}
          <div className="space-y-2.5 max-h-[640px] overflow-y-auto pr-1">
            {filtered.length === 0 ? (
              <div className="p-8 text-center text-[#839496] text-xs">
                {language === "zh" ? "未检索到匹配的证据凭据" : "No artifacts match query."}
              </div>
            ) : (
              filtered.map((ev) => {
                const isSelected = selected?.evidence_id === ev.evidence_id;
                const scoreLabel = ev.evidence_type === "verification_result"
                  ? (language === "zh" ? "复核置信" : "verdict confidence")
                  : (language === "zh" ? "证据可靠度" : "reliability");
                return (
                  <div
                    key={ev.evidence_id}
                    onClick={() => setSelected(ev)}
                    className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer ${
                      isSelected
                        ? "bg-[#eef7f6] border-[#2aa198] shadow-sm ring-1 ring-[#2aa198]/30"
                        : "bg-[#fdfaf3] border-[#dfd6bf] hover:border-[#cbbea2] hover:bg-[#fcf8ed]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border ${getBadgeColor(ev.evidence_type)}`}>
                        {ev.evidence_type.replace("_", " ")}
                      </span>
                      <span className="text-[11px] font-mono text-[#859900] font-bold">
                        {(evidenceScore(ev) * 100).toFixed(0)}% {scoreLabel}
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-[#2b3638] line-clamp-2 leading-snug">
                      {ev.description}
                    </h4>

                    {ev.artifact_path && (
                      <div className="mt-2 text-[10px] font-mono text-[#2aa198] truncate">
                        {ev.artifact_path}
                      </div>
                    )}

                    <div className="flex items-center justify-between text-[10px] text-[#839496] mt-2 pt-2 border-t border-[#dfd6bf] font-mono">
                      <span>{language === "zh" ? "提交智能体: " : "Agent: "}{ev.created_by}</span>
                      <span>{new Date(ev.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Deep Inspector */}
        <div className="lg:col-span-7 space-y-4">
          {selected ? (
            <div className="p-6 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm space-y-5">
              {/* Artifact Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#dfd6bf] pb-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${getBadgeColor(selected.evidence_type)}`}>
                      {selected.evidence_type}
                    </span>
                    <span className="font-mono text-xs text-[#586e75] font-semibold">{selected.evidence_id}</span>
                  </div>
                  <h3 className="text-base font-bold text-[#2b3638]">{selected.description}</h3>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopyJson}
                    className="px-3 py-1.5 rounded-lg bg-[#f5eed9] hover:bg-[#eee8d5] border border-[#dfd6bf] text-xs font-mono text-[#586e75] flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-[#859900]" /> : <Copy className="w-3.5 h-3.5 text-[#2aa198]" />}
                    <span>{copied ? (language === "zh" ? "已复制" : "Copied") : "JSON"}</span>
                  </button>
                </div>
              </div>

              {/* Provenance & Metrics Row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-xl bg-[#f5eed9] border border-[#dfd6bf]">
                  <span className="text-[10px] text-[#586e75] uppercase font-mono block">
                    {selected.evidence_type === "verification_result"
                      ? (language === "zh" ? "复核结论置信度" : "Verdict Confidence")
                      : (language === "zh" ? "证据可靠度" : "Evidence Reliability")}
                  </span>
                  <span className="text-lg font-bold font-mono text-[#859900]">
                    {(evidenceScore(selected) * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-[#f5eed9] border border-[#dfd6bf]">
                  <span className="text-[10px] text-[#586e75] uppercase font-mono block">
                    {language === "zh" ? "提交智能体" : "Creator Agent"}
                  </span>
                  <span className="text-xs font-semibold font-mono text-[#2aa198] truncate block mt-1">
                    {selected.created_by}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-[#f5eed9] border border-[#dfd6bf]">
                  <span className="text-[10px] text-[#586e75] uppercase font-mono block">
                    {language === "zh" ? "验证互认状态" : "Verification Status"}
                  </span>
                  <span className="text-xs font-semibold font-mono text-[#859900] flex items-center gap-1 mt-1">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    {language === "zh" ? "多源互证成立" : "Corroborated"}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-[#f5eed9] border border-[#dfd6bf]">
                  <span className="text-[10px] text-[#586e75] uppercase font-mono block">
                    {language === "zh" ? "采样生成时间" : "Timestamp"}
                  </span>
                  <span className="text-xs font-mono text-[#586e75] truncate block mt-1">
                    {new Date(selected.created_at).toLocaleTimeString()}
                  </span>
                </div>
              </div>

              {/* Path Display */}
              {selected.artifact_path && (
                <div className="p-3 rounded-xl bg-[#f5eed9] border border-[#dfd6bf] text-xs font-mono text-[#586e75] flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-[#2aa198] shrink-0" />
                  <span className="text-[#586e75]">{language === "zh" ? "关联工件文件:" : "Artifact File:"}</span>
                  <span className="text-[#2aa198] select-all font-medium">{selected.artifact_path}</span>
                </div>
              )}

              {/* Interactive Code / Assembly / Crash Dump Viewer */}
              {selected.data?.code_snippet ? (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-[#2b3638] flex items-center gap-1.5">
                      <Code className="w-3.5 h-3.5 text-[#2aa198]" />
                      {language === "zh" ? "源码或反编译证据片段" : "Source or Decompiled Evidence Snippet"}
                    </span>
                    <span className="text-[10px] font-mono text-[#839496]">
                      {language === "zh" ? "代码行" : "Lines"} {selected.data.line_start} - {selected.data.line_end}
                    </span>
                  </div>

                  <div className="rounded-xl bg-[#fcf8ed] border border-[#dfd6bf] overflow-hidden font-mono text-xs shadow-2xs">
                    <div className="px-4 py-2 bg-[#eee8d5] border-b border-[#dfd6bf] flex items-center justify-between text-[11px] text-[#586e75]">
                      <span>{selected.evidence_type.replaceAll("_", " ").toUpperCase()}</span>
                      <span className="text-[#2aa198] font-bold">
                        {language === "zh" ? `来源：${selected.source}` : `Source: ${selected.source}`}
                      </span>
                    </div>
                    <pre className="p-4 overflow-x-auto text-[#2b3638] leading-relaxed bg-[#fdfaf3]">
                      {selected.data.code_snippet}
                    </pre>
                  </div>
                </div>
              ) : selected.data?.sanitizer_output || selected.data?.saved_rip ? (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-[#2b3638] flex items-center gap-1.5">
                      <Bug className="w-3.5 h-3.5 text-[#dc322f]" />
                      {language === "zh" ? "受控运行崩溃现场与诊断数据" : "Controlled Runtime Crash & Diagnostics"}
                    </span>
                    <span className="text-[10px] font-mono text-[#dc322f] font-bold">
                      {selected.data.signal || (language === "zh" ? "已记录崩溃" : "CRASH RECORDED")}
                    </span>
                  </div>

                  <div className="space-y-3">
                    {/* Register State Card */}
                    {selected.data.saved_rip && (
                      <div className="grid grid-cols-2 gap-3 font-mono text-xs">
                        <div className="p-2.5 rounded-lg bg-[#fce8e6] border border-[#f5b8b5] text-[#dc322f]">
                          <span className="text-[10px] text-[#586e75] uppercase block">
                            {language === "zh" ? "被覆盖的 RIP 寄存器值" : "Overwritten RIP Register"}
                          </span>
                          <span className="font-bold text-[#dc322f]">{selected.data.saved_rip}</span>
                        </div>
                        <div className="p-2.5 rounded-lg bg-[#fbf4e6] border border-[#ecd8a6] text-[#b58900]">
                          <span className="text-[10px] text-[#586e75] uppercase block">
                            {language === "zh" ? "崩溃触发指令" : "Faulting Opcode"}
                          </span>
                          <span className="font-bold text-[#b58900]">{selected.data.faulting_instruction}</span>
                        </div>
                      </div>
                    )}

                    {/* Sanitizer Terminal Output */}
                    {selected.data.sanitizer_output && (
                      <div className="p-4 rounded-xl bg-[#263238] border border-[#dc322f]/60 font-mono text-xs text-[#fdf6e3] overflow-x-auto leading-relaxed whitespace-pre-wrap">
                        {selected.data.sanitizer_output}
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div>
                  <label className="text-xs font-semibold text-[#2b3638] block mb-2">
                    {language === "zh" ? "结构化证据原始数据 (JSON)" : "Structured Evidence Data"}
                  </label>
                  <pre className="p-4 rounded-xl bg-[#f5eed9] border border-[#dfd6bf] text-xs font-mono text-[#2b3638] overflow-x-auto whitespace-pre-wrap max-h-[300px]">
                    {JSON.stringify(selected.data, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="p-16 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] text-center text-[#839496] text-xs">
              {language === "zh" ? "请在左侧列表选择证据以查看结构化详情" : "Select an evidence record on the left to inspect its structured data."}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
