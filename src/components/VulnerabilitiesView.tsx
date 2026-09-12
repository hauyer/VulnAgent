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
  Save,
  MessageSquareText,
} from "lucide-react";
import {
  VulnerabilityCandidate,
  Evidence,
  VulnerabilityStatus,
  HumanReviewAnnotation,
  HumanReviewDecision,
} from "../types.js";
import { useTranslation } from "../i18n.js";

interface VulnerabilitiesViewProps {
  taskId: string;
  findings: VulnerabilityCandidate[];
  evidenceList: Evidence[];
  onInspectEvidence: (evidenceId: string) => void;
  onReviewSaved?: (annotation: HumanReviewAnnotation) => void | Promise<void>;
}

export const VulnerabilitiesView: React.FC<VulnerabilitiesViewProps> = ({
  taskId,
  findings,
  evidenceList,
  onInspectEvidence,
  onReviewSaved,
}) => {
  const { t, language } = useTranslation();
  const [selectedStatus, setSelectedStatus] = useState<string>("all");
  const [selectedDomain, setSelectedDomain] = useState<"all" | "ai_interaction" | "software_code">("all");
  const [selectedType, setSelectedType] = useState<string>("all");
  const [detailTab, setDetailTab] = useState<"source" | "flow" | "validation">("source");
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityCandidate | null>(
    findings[0] || null
  );
  const [annotations, setAnnotations] = useState<HumanReviewAnnotation[]>([]);
  const [reviewDecision, setReviewDecision] = useState<HumanReviewDecision>("needs_followup");
  const [reviewNote, setReviewNote] = useState("");
  const [savingReview, setSavingReview] = useState(false);
  const [reviewSaved, setReviewSaved] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);

  React.useEffect(() => {
    if (!selectedFinding && findings.length > 0) {
      setSelectedFinding(findings[0]);
    }
  }, [findings, selectedFinding]);

  React.useEffect(() => {
    fetch(`/api/tasks/${taskId}/reviews`)
      .then((response) => (response.ok ? response.json() : []))
      .then((items: HumanReviewAnnotation[]) => setAnnotations(items))
      .catch(() => setAnnotations([]));
  }, [taskId]);

  React.useEffect(() => {
    if (!selectedFinding) return;
    const annotation = annotations.find(
      (item) => item.vulnerability_id === selectedFinding.vulnerability_id,
    );
    setReviewDecision(annotation?.decision || "needs_followup");
    setReviewNote(annotation?.note || "");
  }, [selectedFinding?.vulnerability_id, annotations]);

  React.useEffect(() => {
    setReviewSaved(false);
    setReviewError(null);
  }, [selectedFinding?.vulnerability_id]);

  const saveReview = async () => {
    if (!selectedFinding || savingReview) return;
    setSavingReview(true);
    setReviewSaved(false);
    setReviewError(null);
    try {
      const response = await fetch(
        `/api/tasks/${taskId}/findings/${selectedFinding.vulnerability_id}/review`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            decision: reviewDecision,
            note: reviewNote,
            reviewer: "course-reviewer",
          }),
        },
      );
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(
          typeof body.detail === "string"
            ? body.detail
            : language === "zh"
              ? "人工标注保存失败"
              : "Unable to save the human review annotation",
        );
      }
      const saved: HumanReviewAnnotation = await response.json();
      setAnnotations((items) => [
        ...items.filter((item) => item.vulnerability_id !== saved.vulnerability_id),
        saved,
      ]);
      setReviewSaved(true);
      try {
        await onReviewSaved?.(saved);
      } catch {
        setReviewError(
          language === "zh"
            ? "标注已保存，但审计报告刷新失败；请点击顶部刷新后重试。"
            : "The annotation was saved, but the report refresh failed. Refresh the workspace and try again.",
        );
      }
    } catch (error) {
      setReviewError(
        error instanceof Error
          ? error.message
          : language === "zh"
            ? "人工标注保存失败"
            : "Unable to save the human review annotation",
      );
    } finally {
      setSavingReview(false);
    }
  };

  const isSoftwareCodeFinding = (finding: VulnerabilityCandidate) =>
    finding.metadata?.audit_domain === "software_code"
    || [
      "integer_overflow", "integer_underflow", "integer_boundary_error",
      "buffer_overflow", "stack_buffer_overflow", "heap_buffer_overflow",
      "array_out_of_bounds", "input_validation_missing", "null_pointer_dereference",
      "resource_leak", "interface_access_control_missing", "configuration_authorization_missing",
    ].includes(finding.vulnerability_type);
  const domainFiltered = findings.filter((f) => {
    if (selectedType !== "all" && f.vulnerability_type !== selectedType && f.metadata?.risk_subtype !== selectedType) return false;
    if (selectedDomain === "software_code" && !isSoftwareCodeFinding(f)) return false;
    if (selectedDomain === "ai_interaction" && isSoftwareCodeFinding(f)) return false;
    return true;
  });
  const filtered = domainFiltered.filter((f) => selectedStatus === "all" || f.status === selectedStatus);
  const vulnerabilityTypes = Array.from(new Set(findings.flatMap((item) => [item.vulnerability_type, item.metadata?.risk_subtype].filter(Boolean) as string[]))).sort();

  React.useEffect(() => {
    if (!selectedFinding || !filtered.some((item) => item.vulnerability_id === selectedFinding.vulnerability_id)) {
      setSelectedFinding(filtered[0] || null);
    }
  }, [selectedDomain, selectedStatus, selectedType, findings]);

  const confirmedCount = findings.filter((f) => f.status === "confirmed").length;
  const uncertainCount = findings.filter((f) => f.status === "uncertain").length;
  const selectedEvidence = selectedFinding
    ? evidenceList.filter((item) =>
        selectedFinding.evidence_ids.includes(item.evidence_id)
        || item.data?.finding_id === selectedFinding.vulnerability_id
        || item.data?.vulnerability_id === selectedFinding.vulnerability_id,
      )
    : [];
  const selectedEvidenceTypes = Array.from(
    new Set(selectedEvidence.map((item) => item.evidence_type.replaceAll("_", " "))),
  ).join(", ");
  const hasVerificationEvidence = selectedEvidence.some(
    (item) => item.evidence_type === "verification_result",
  );
  const selectedLocation = selectedFinding?.location;
  const locationEvidence = selectedEvidence.find((item) =>
    ["source_location", "binary_address", "disassembly"].includes(item.evidence_type),
  );
  const locationEvidenceData = locationEvidence?.data || {};
  const cfgEvidence = selectedEvidence.find((item) => item.evidence_type === "cfg_path");
  const taintEvidence = selectedEvidence.find((item) => ["taint_path", "data_flow"].includes(item.evidence_type));
  const validationEvidence = selectedEvidence.filter((item) =>
    ["runtime_trace", "crash_log", "sanitizer_output", "verification_result"].includes(item.evidence_type),
  );
  const cfgPath = Array.isArray(selectedFinding?.metadata?.cfg_path)
    ? selectedFinding.metadata.cfg_path
    : Array.isArray(cfgEvidence?.data?.path) ? cfgEvidence.data.path : [];
  const taintPath = Array.isArray(selectedFinding?.metadata?.taint_path)
    ? selectedFinding.metadata.taint_path
    : Array.isArray(taintEvidence?.data?.path) ? taintEvidence.data.path : [];
  const isBinaryFinding = Boolean(
    selectedFinding && (
      selectedFinding.source_type === "binary"
      || selectedLocation?.binary_address
      || (selectedLocation?.module_name && !selectedLocation?.file_path)
    )
  );
  const binaryModule = selectedLocation?.module_name || locationEvidenceData.module_name || locationEvidenceData.path;
  const binaryAddress = selectedLocation?.binary_address || locationEvidenceData.binary_address || locationEvidenceData.pseudocode_address;
  const binaryOffset = selectedFinding?.metadata?.binary_file_offset || locationEvidenceData.binary_file_offset;
  const locatedFunction = selectedLocation?.function_name || locationEvidenceData.function;
  const locatorKind = selectedFinding?.metadata?.locator_kind || locationEvidenceData.locator_kind;
  const matchedSymbols = Array.from(new Set(
    [
      ...(Array.isArray(selectedFinding?.metadata?.matched_symbols) ? selectedFinding.metadata.matched_symbols : []),
      ...(Array.isArray(locationEvidenceData.matched_symbols) ? locationEvidenceData.matched_symbols : []),
      selectedFinding?.metadata?.located_symbol,
      locationEvidenceData.located_symbol,
    ]
      .map((item) => String(item || "").trim())
      .filter(Boolean),
  ));
  const moduleFilename = String(binaryModule || "")
    .split(/[\\/]/)
    .filter(Boolean)
    .at(-1);
  const locationPrecisionLabel = selectedLocation?.file_path
    ? selectedLocation.line_start
      ? "SOURCE LINE"
      : "SOURCE FILE"
    : binaryAddress
      ? locatorKind === "import_table"
        ? "IAT ADDRESS"
        : locatorKind === "decoded_callsite"
          ? "CALL SITE"
          : "VIRTUAL ADDRESS"
      : binaryOffset
        ? "FILE OFFSET"
        : binaryModule
          ? "IMAGE + SYMBOL"
          : "UNRESOLVED";

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
          <div className="grid grid-cols-3 gap-1 rounded-xl border border-[#dfd6bf] bg-[#eee8d5] p-1 text-xs">
            {([
              ["all", language === "zh" ? "全部风险" : "All"],
              ["ai_interaction", language === "zh" ? "AI 交互安全" : "AI safety"],
              ["software_code", language === "zh" ? "代码安全" : "Code security"],
            ] as const).map(([value, label]) => (
              <button
                key={value}
                type="button"
                onClick={() => { setSelectedDomain(value); setSelectedType("all"); }}
                className={`rounded-lg px-2 py-2 font-semibold transition-colors ${selectedDomain === value ? "bg-[#2aa198] text-white shadow-sm" : "text-[#586e75] hover:bg-[#fdfaf3]"}`}
              >
                {label}
              </button>
            ))}
          </div>
          <select
            value={selectedType}
            onChange={(event) => setSelectedType(event.target.value)}
            className="w-full rounded-lg border border-[#dfd6bf] bg-[#fdfaf3] px-3 py-2 text-xs text-[#2b3638] outline-none focus:border-[#2aa198]"
          >
            <option value="all">{language === "zh" ? "全部漏洞类型" : "All vulnerability types"}</option>
            {vulnerabilityTypes.map((type) => <option key={type} value={type}>{type.replaceAll("_", " ")}</option>)}
          </select>
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
                {getStatusLabel(st)} ({domainFiltered.filter((f) => st === "all" || f.status === st).length})
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

              {/* Source/binary location and traceability */}
              <div className="p-4 rounded-xl bg-[#f5eed9] border border-[#dfd6bf] space-y-3 text-xs">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="flex items-start gap-2 min-w-0">
                    <FileCode className="w-4 h-4 text-[#2aa198] mt-0.5 shrink-0" />
                    <div className="min-w-0">
                      <span className="text-[#586e75] font-semibold block">
                        {language === "zh"
                          ? isBinaryFinding ? "目标二进制定位" : "目标源码位置"
                          : isBinaryFinding ? "Binary Target Location" : "Source Location"}
                      </span>
                      {selectedLocation?.file_path ? (
                        <div className="mt-1 font-mono text-[#2b3638] break-all">
                          {selectedLocation.file_path}
                          {selectedLocation.line_start && `:${selectedLocation.line_start}`}
                          {selectedLocation.line_end && selectedLocation.line_end !== selectedLocation.line_start
                            ? `-${selectedLocation.line_end}`
                            : ""}
                        </div>
                      ) : (
                        <div className="mt-1">
                          <div className="font-mono font-bold text-[#2b3638]">
                            {binaryAddress
                              ? `${language === "zh" ? "虚拟地址" : "Virtual address"} ${binaryAddress}`
                              : binaryOffset
                                ? `${language === "zh" ? "文件偏移" : "File offset"} ${binaryOffset}`
                                : moduleFilename || (language === "zh" ? "尚未获得可靠地址" : "No reliable address available")}
                          </div>
                          {binaryModule && (
                            <div className="mt-1 font-mono text-[10px] text-[#839496] break-all" title={String(binaryModule)}>
                              {language === "zh" ? "分析映像" : "Analyzed image"}: {String(binaryModule)}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                  <span className="px-2 py-1 rounded-md border border-[#bfe3e0] bg-[#eef7f6] text-[#2aa198] text-[10px] font-mono font-bold">
                    {locationPrecisionLabel}
                  </span>
                </div>

                {(locatedFunction || matchedSymbols.length > 0) && (
                  <div className="flex items-center gap-2 flex-wrap font-mono">
                    {locatedFunction && (
                      <span className="px-2 py-1 rounded-md bg-[#fdfaf3] border border-[#dfd6bf] text-[#2aa198] font-semibold">
                        fn {locatedFunction}()
                      </span>
                    )}
                    {matchedSymbols.map((symbol) => (
                      <span key={symbol} className="px-2 py-1 rounded-md bg-[#fbf4e6] border border-[#ecd8a6] text-[#9b6f00]">
                        {language === "zh" ? "命中符号" : "Matched symbol"} · {symbol}
                      </span>
                    ))}
                  </div>
                )}

                <div className="flex items-start justify-between gap-3 flex-wrap border-t border-[#dfd6bf] pt-3">
                  <p className="text-[11px] leading-relaxed text-[#586e75] flex-1 min-w-[240px]">
                    {isBinaryFinding
                      ? binaryAddress || binaryOffset
                        ? language === "zh"
                          ? "已定位到二进制地址/偏移，可结合逆向伪代码、反汇编和 CFG 追溯；PE/ELF 未携带 PDB、DWARF 或源码映射时，不能诚实还原为原始源码文件与行号。"
                          : "A binary address/offset is available for reverse-code, disassembly and CFG traceability. Original source lines require PDB, DWARF or a source map."
                        : language === "zh"
                          ? "当前只能定位到二进制映像及命中符号，尚未恢复出可靠的函数/指令地址；无调试符号的 PE/ELF 不能直接追溯为原始源码行。"
                          : "Only the binary image and matched symbol are available; no reliable function/instruction address was recovered. Source lines require debug mapping."
                      : language === "zh"
                        ? "源码目标可按文件、函数与行号直接回溯。"
                        : "Source targets are traceable by file, function and line."}
                  </p>
                  {locationEvidence && (
                    <button
                      type="button"
                      onClick={() => onInspectEvidence(locationEvidence.evidence_id)}
                      className="px-3 py-1.5 rounded-lg bg-[#2aa198] text-white text-[11px] font-semibold hover:bg-[#238c82] transition-colors cursor-pointer flex items-center gap-1.5 shrink-0"
                    >
                      {language === "zh" ? "查看定位证据" : "Inspect location evidence"}
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>

              {isSoftwareCodeFinding(selectedFinding) && (
                <div className="rounded-xl border border-[#bfe3e0] bg-[#eef7f6] overflow-hidden">
                  <div className="grid grid-cols-3 border-b border-[#bfe3e0] text-xs font-semibold">
                    {([
                      ["source", language === "zh" ? "源码定位" : "Source"],
                      ["flow", language === "zh" ? "控制流路径" : "Control flow"],
                      ["validation", language === "zh" ? "验证日志" : "Validation"],
                    ] as const).map(([value, label]) => (
                      <button
                        key={value}
                        type="button"
                        onClick={() => setDetailTab(value)}
                        className={`px-3 py-2.5 ${detailTab === value ? "bg-[#2aa198] text-white" : "text-[#586e75] hover:bg-white/50"}`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                  <div className="p-4 text-xs text-[#586e75]">
                    {detailTab === "source" && (
                      <div className="space-y-2">
                        <div className="font-mono text-[#2b3638] break-all">
                          {selectedLocation?.file_path || (language === "zh" ? "暂无源码文件定位" : "No source location")}
                          {selectedLocation?.line_start ? `:${selectedLocation.line_start}` : ""}
                          {selectedLocation?.function_name ? ` · ${selectedLocation.function_name}()` : ""}
                        </div>
                        {selectedEvidence.filter((item) => item.evidence_type === "code_snippet").map((item) => (
                          <pre key={item.evidence_id} className="overflow-x-auto rounded-lg border border-[#dfd6bf] bg-[#fdfaf3] p-3 text-[11px] text-[#2b3638] whitespace-pre-wrap">{String(item.data?.snippet || item.description)}</pre>
                        ))}
                      </div>
                    )}
                    {detailTab === "flow" && (
                      <div className="grid gap-3 sm:grid-cols-2">
                        <div>
                          <div className="font-bold text-[#2aa198] mb-2">CFG</div>
                          {cfgPath.length ? cfgPath.map((node: any, index: number) => (
                            <div key={`${node.node_id || index}`} className="border-l-2 border-[#2aa198] pl-2 pb-2 font-mono text-[11px]">
                              L{node.line || "?"} · {node.node_type || "statement"}<div className="text-[#839496] break-words">{node.text || node.node_id}</div>
                            </div>
                          )) : <div>{language === "zh" ? "暂无 CFG 路径" : "No CFG path"}</div>}
                        </div>
                        <div>
                          <div className="font-bold text-[#6c71c4] mb-2">TAINT</div>
                          {taintPath.length ? taintPath.map((step: any, index: number) => (
                            <div key={`${String(step)}-${index}`} className="border-l-2 border-[#6c71c4] pl-2 pb-2 font-mono text-[11px] break-words">{typeof step === "string" ? step : JSON.stringify(step)}</div>
                          )) : <div>{language === "zh" ? "暂无污点路径" : "No taint path"}</div>}
                        </div>
                      </div>
                    )}
                    {detailTab === "validation" && (
                      <div className="space-y-2">
                        {validationEvidence.length ? validationEvidence.map((item) => (
                          <button key={item.evidence_id} type="button" onClick={() => onInspectEvidence(item.evidence_id)} className="w-full rounded-lg border border-[#dfd6bf] bg-[#fdfaf3] p-3 text-left hover:border-[#2aa198]">
                            <div className="flex justify-between gap-3"><span className="font-mono font-bold text-[#2aa198]">{item.evidence_type}</span><span className="font-mono text-[10px]">{Math.round(item.reliability * 100)}%</span></div>
                            <p className="mt-1">{item.description}</p>
                            {item.data?.anomaly_count !== undefined && <p className="mt-1 font-mono text-[10px]">cases={item.data.case_count || 0} · anomalies={item.data.anomaly_count} · reset={String(item.data.reset_completed)}</p>}
                          </button>
                        )) : <div>{language === "zh" ? "尚未形成动态或独立复核日志" : "No dynamic or verification log yet"}</div>}
                        <p className="text-[10px] text-[#839496]">{language === "zh" ? "仅展示状态、异常和复核摘要；不展示测试输入内容。" : "Only stability and verdict summaries are shown; test inputs are hidden."}</p>
                      </div>
                    )}
                  </div>
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
              <div className="p-4 rounded-xl bg-[#f5eed9] border border-[#dfd6bf] space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-semibold text-[#2b3638] flex items-center gap-2">
                    <MessageSquareText className="w-4 h-4 text-[#6c71c4]" />
                    {language === "zh" ? "人工复核与标注修正" : "Human review annotation"}
                  </span>
                  <span className="text-[10px] text-[#839496] font-mono">
                    {language === "zh" ? "不覆盖 Verification 状态" : "Does not override Verification"}
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-[180px_1fr] gap-2">
                  <select
                    value={reviewDecision}
                    onChange={(event) => {
                      setReviewDecision(event.target.value as HumanReviewDecision);
                      setReviewSaved(false);
                      setReviewError(null);
                    }}
                    className="rounded-lg border border-[#dfd6bf] bg-[#fdfaf3] px-3 py-2 text-xs text-[#2b3638] outline-none focus:border-[#6c71c4]"
                  >
                    <option value="accepted">{language === "zh" ? "接受复核结论" : "Accept verdict"}</option>
                    <option value="rejected">{language === "zh" ? "人工判定需修正" : "Mark for correction"}</option>
                    <option value="needs_followup">{language === "zh" ? "需要后续复核" : "Needs follow-up"}</option>
                  </select>
                  <textarea
                    value={reviewNote}
                    onChange={(event) => {
                      setReviewNote(event.target.value);
                      setReviewSaved(false);
                      setReviewError(null);
                    }}
                    rows={3}
                    maxLength={4000}
                    placeholder={language === "zh" ? "记录复核依据、修正意见或待补证据…" : "Record rationale, correction, or missing evidence…"}
                    className="rounded-lg border border-[#dfd6bf] bg-[#fdfaf3] px-3 py-2 text-xs text-[#2b3638] outline-none focus:border-[#6c71c4] resize-y"
                  />
                </div>
                <button
                  type="button"
                  onClick={saveReview}
                  disabled={savingReview}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-[#6c71c4] hover:bg-[#5d63b3] text-white px-3 py-2 text-xs font-bold disabled:opacity-50"
                >
                  {reviewSaved ? <Check className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
                  {reviewSaved
                    ? (language === "zh" ? "已保存并写入报告投影" : "Saved into report projection")
                    : (language === "zh" ? "保存人工标注" : "Save annotation")}
                </button>
                {reviewSaved && !reviewError && (
                  <p role="status" className="text-xs font-medium text-[#6b7d00]">
                    {language === "zh"
                      ? "保存成功，审计报告中的人工复核标注已同步。"
                      : "Saved successfully. The report's human review projection is synchronized."}
                  </p>
                )}
                {reviewError && (
                  <p role="alert" className="text-xs font-medium text-[#dc322f]">
                    {reviewError}
                  </p>
                )}
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
