import React from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Code2,
  FileSearch,
  FileText,
  GitBranch,
  Search,
  ShieldCheck,
  Tag,
  Wrench,
} from "lucide-react";
import { Evidence } from "../types.js";
import {
  protectionMethodLabel,
  signalCode,
  signalEvidence,
  uniqueProtectionMethods,
} from "../protectionMethods.js";

interface BinaryReverseWorkbenchProps {
  evidenceList: Evidence[];
  onOpenReview: () => void;
  onOpenReport: () => void;
}

type JsonMap = Record<string, any>;

const asMap = (value: unknown): JsonMap =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as JsonMap) : {};

const asArray = (value: unknown): JsonMap[] =>
  Array.isArray(value) ? value.filter((item) => item && typeof item === "object") : [];

const asStrings = (value: unknown): string[] =>
  Array.isArray(value) ? value.map(String).filter(Boolean) : [];

const addressOf = (item: JsonMap): string => {
  if (typeof item.address === "number") return `0x${item.address.toString(16)}`;
  return typeof item.address === "string" ? item.address : "";
};

const STAGE_LABEL: Record<string, string> = {
  structural_parse: "结构解析",
  unpack: "去壳决策",
  decompile: "反编译",
  semantic_logic: "语义标定",
  vulnerability_rules: "缺陷检测",
  independent_verification: "独立复核",
};

const CATEGORY_LABEL: Record<string, string> = {
  authentication: "认证逻辑",
  cryptography: "加解密逻辑",
  registration: "注册/授权逻辑",
  network_input: "网络输入",
  memory_operation: "内存操作",
};

export const BinaryReverseWorkbench: React.FC<BinaryReverseWorkbenchProps> = ({
  evidenceList,
  onOpenReview,
  onOpenReport,
}) => {
  const summaryEvidence = evidenceList.find(
    (item) => item.source === "binary_reverse" && item.evidence_type === "tool_result",
  );
  const codeEvidence = evidenceList.find(
    (item) => item.source === "binary_reverse" && item.evidence_type === "disassembly",
  );
  const cfgEvidence = evidenceList.find(
    (item) => item.source === "binary_reverse" && item.evidence_type === "cfg_path",
  );
  const logicEvidence = evidenceList.find((item) => item.source === "binary_logic");
  const obfuscationEvidence = evidenceList.find((item) => item.source === "binary_obfuscation");
  const restorationEvidence = evidenceList.find((item) => item.source === "program_restoration");
  const deobfuscationEvidence = evidenceList.find((item) => item.source === "code_deobfuscation");

  const summary = asMap(summaryEvidence?.data);
  const codeData = asMap(codeEvidence?.data);
  const cfgData = asMap(cfgEvidence?.data);
  const pseudocode = asMap(codeData.pseudocode);
  const functions = asArray(codeData.functions);
  const cfg = asMap(cfgData.cfg);
  const logicData = asMap(logicEvidence?.data);
  const logicLocations = asArray(logicData.locations);
  const deobfuscation = asMap(logicData.deobfuscation);
  const decodedStrings = asArray(deobfuscation.items);
  const obfuscationData = asMap(obfuscationEvidence?.data);
  const restorationData = asMap(restorationEvidence?.data);
  const protectionAssessment = asMap(restorationData.protection);
  const selectedProtection = asMap(protectionAssessment.selected);
  const restorationMetrics = asMap(restorationData.metrics);
  const restorationValidation = asMap(restorationData.validation);
  const restorationRecords = asArray(restorationData.records);
  const dynamicRecoveryCompleted = restorationRecords.some(
    (item) => ["dynamic_snapshot", "frida_dex_capture"].includes(String(item.stage)) && item.status === "completed",
  );
  const deobfuscationData = asMap(deobfuscationEvidence?.data);
  const deobfuscationReadability = asMap(deobfuscationData.readability);
  const deobfuscationFunctions = asArray(asMap(deobfuscationData.instruction_recovery).functions);
  const packingSignals = asMap(summary.packing_signals);
  const signalItems = asArray(obfuscationData.signals);
  const declaredProtection = String(
    obfuscationData.declared_protection || summary.declared_protection || "",
  ).trim();
  const protectionCategory = String(
    obfuscationData.protection_category || summary.protection_category || "",
  );
  const observedMethods = uniqueProtectionMethods([
    ...asStrings(summary.observed_protection_methods),
    ...asStrings(obfuscationData.observed_methods),
    ...asStrings(packingSignals.signals),
    ...signalItems.map(signalCode),
    selectedProtection.code,
  ]);
  const recoveryMethods = uniqueProtectionMethods([
    ...(summary.derived_from_unpack || observedMethods.includes("upx_unpack_copy") ? ["upx_unpack_copy"] : []),
    ...decodedStrings.map((item) => `${String(item.encoding || "").toLowerCase()}_decode`),
    ...asStrings(deobfuscationData.detected_types),
  ]);
  const plan = asMap(summary.analysis_plan);
  const decisions = asMap(plan.decisions);
  const stages = asArray(plan.steps);
  const toolRuns = asArray(summary.tool_runs);
  const codeAddresses = Object.keys(pseudocode);
  const verificationCompleted = evidenceList.some((item) => item.evidence_type === "verification_result");

  const [query, setQuery] = React.useState("");
  const [selectedAddress, setSelectedAddress] = React.useState(codeAddresses[0] || addressOf(functions[0] || {}));

  React.useEffect(() => {
    const available = Object.keys(pseudocode);
    if (!selectedAddress || (!available.includes(selectedAddress) && available.length > 0)) {
      setSelectedAddress(available[0] || addressOf(functions[0] || {}));
    }
  }, [codeEvidence?.evidence_id]);

  const filteredFunctions = functions.filter((item) => {
    const value = `${item.name || ""} ${addressOf(item)}`.toLowerCase();
    return value.includes(query.trim().toLowerCase());
  });
  const selectedFunction = functions.find((item) => addressOf(item) === selectedAddress);
  const selectedCode = String(pseudocode[selectedAddress] || "");
  const selectedEdges = Array.isArray(cfg[selectedAddress]) ? cfg[selectedAddress].map(String) : [];
  const hasReverseEvidence = Boolean(summaryEvidence || codeEvidence || cfgEvidence || logicEvidence || obfuscationEvidence || restorationEvidence || deobfuscationEvidence);

  if (!hasReverseEvidence) {
    return (
      <div className="rounded-2xl border border-dashed border-[#cbbf9f] bg-[#fbf7eb] p-10 text-center">
        <FileSearch className="mx-auto h-8 w-8 text-[#93a1a1]" />
        <h3 className="mt-3 font-bold text-[#2b3638]">当前任务没有二进制逆向产物</h3>
        <p className="mx-auto mt-2 max-w-2xl text-xs leading-relaxed text-[#586e75]">
          请从“漏洞测试实验室”的加壳软件或混淆软件入口提交本地 PE/ELF/DEX/APK，确认授权后运行。
          普通任务不会自动调用去壳与反编译工具。
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <section className="overflow-hidden rounded-2xl border border-[#c8d7d2] bg-[#fdfaf3] shadow-sm">
        <div className="flex flex-col gap-4 border-b border-[#dce5df] bg-[linear-gradient(120deg,#eaf6f3,#fbf6e8)] p-5 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <div className="flex items-center gap-2 text-[11px] font-mono font-bold uppercase tracking-[0.16em] text-[#2aa198]">
              <Code2 className="h-4 w-4" /> Binary Reverse Workbench
            </div>
            <h3 className="mt-1 text-xl font-black text-[#243234]">二进制逆向与可读伪代码工作台</h3>
            <p className="mt-1 max-w-3xl text-xs leading-relaxed text-[#586e75]">
              展示智能体规划、还原/反编译产物、控制流关系与关键业务逻辑标定；默认使用静态事实，隔离动态 Provider 的结果会单独标识并留证。
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={onOpenReview} className="inline-flex items-center gap-1.5 rounded-lg border border-[#b7d8d2] bg-white px-3 py-2 text-xs font-bold text-[#147f79] hover:bg-[#eef7f6]">
              <ShieldCheck className="h-3.5 w-3.5" />人工复核与修正
            </button>
            <button onClick={onOpenReport} className="inline-flex items-center gap-1.5 rounded-lg bg-[#2aa198] px-3 py-2 text-xs font-bold text-white hover:bg-[#238d86]">
              <FileText className="h-3.5 w-3.5" />打开/导出报告
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-px bg-[#dce5df] sm:grid-cols-3 xl:grid-cols-6">
          {[
            ["函数", summary.function_count ?? functions.length],
            ["伪代码", summary.pseudocode_count ?? codeAddresses.length],
            ["CFG 节点", summary.cfg_node_count ?? Object.keys(cfg).length],
            ["分析映像", summary.derived_from_unpack ? "去壳副本" : "原始文件"],
            ["结构校验", restorationValidation.parseable === true ? "可解析" : restorationData.status || "未执行"],
            ["可读性", deobfuscationReadability.after !== undefined ? `${deobfuscationReadability.before || 0}→${deobfuscationReadability.after}` : "—"],
          ].map(([label, value]) => (
            <div key={String(label)} className="bg-[#fdfaf3] px-4 py-3">
              <div className="text-[10px] font-mono uppercase text-[#839496]">{label}</div>
              <div className="mt-0.5 text-lg font-black text-[#2b3638]">{String(value)}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-2xl border border-[#c9dcd7] bg-[linear-gradient(135deg,#f7fbf7,#f7f3e7)] p-4 shadow-sm">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold text-[#2b3638]">
              <Tag className="h-4 w-4 text-[#2aa198]" />保护与混淆方法归因
            </div>
            <p className="mt-1 text-[11px] leading-relaxed text-[#586e75]">
              将样本声明、系统静态观察和实际反混淆动作分栏展示；声明信息不作为检测结论。
            </p>
          </div>
          <span className="w-fit rounded-full border border-[#bfe3e0] bg-white px-2.5 py-1 text-[10px] font-mono font-bold text-[#2aa198]">
            {protectionCategory === "packed_binary" ? "PACKING" : protectionCategory === "obfuscated_binary" ? "OBFUSCATION" : "BINARY"}
          </span>
        </div>
        <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
          <div className="rounded-xl border border-[#dfd6bf] bg-white/80 p-3">
            <div className="text-[10px] font-mono font-bold text-[#b58900]">01 · 样本声明 DECLARED</div>
            <div className="mt-2 text-sm font-bold text-[#2b3638]">
              {declaredProtection || "未声明具体保护器"}
            </div>
            <p className="mt-1 text-[10px] text-[#839496]">来自授权上传信息或样本台账，仅作归因参考。</p>
          </div>
          <div className="rounded-xl border border-[#bfe3e0] bg-white/80 p-3">
            <div className="text-[10px] font-mono font-bold text-[#2aa198]">02 · 静态观察 OBSERVED</div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {observedMethods.length ? observedMethods.map((method) => (
                <span key={method} className="rounded-full border border-[#bfe3e0] bg-[#eef7f6] px-2 py-1 text-[10px] font-semibold text-[#147f79]">
                  {protectionMethodLabel(method)}
                </span>
              )) : <span className="text-xs text-[#839496]">未观察到可归因的静态信号</span>}
            </div>
            {selectedProtection.family && (
              <p className="mt-2 text-[10px] font-semibold text-[#147f79]">
                识别：{String(selectedProtection.family)} · L{String(selectedProtection.level || 0)} · 置信度 {Math.round(Number(selectedProtection.confidence || 0) * 100)}%
              </p>
            )}
            <p className="mt-2 text-[10px] text-[#839496]">由区段、导入、入口点、字符串和反调试事实生成。</p>
          </div>
          <div className="rounded-xl border border-[#d8d3ec] bg-white/80 p-3">
            <div className="text-[10px] font-mono font-bold text-[#6c71c4]">03 · 反混淆动作 RECOVERY</div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {recoveryMethods.length ? recoveryMethods.map((method) => (
                <span key={method} className="rounded-full border border-[#d8d3ec] bg-[#f4f1f9] px-2 py-1 text-[10px] font-semibold text-[#6c71c4]">
                  {protectionMethodLabel(method)}
                </span>
              )) : <span className="text-xs text-[#839496]">本次未执行确定性还原</span>}
            </div>
            <p className="mt-2 text-[10px] text-[#839496]">只记录实际发生的副本脱壳或字符串确定性还原。</p>
          </div>
        </div>
      </section>

      {(restorationEvidence || deobfuscationEvidence) && (
        <section className="rounded-2xl border border-[#c9dcd7] bg-[#fdfaf3] p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="text-xs font-bold text-[#2b3638]">还原质量与策略反馈</div>
              <p className="mt-1 text-[11px] text-[#586e75]">区分“识别完成”“生成副本”和“通过反编译前结构校验”，不以计划代替执行结果。</p>
            </div>
            <div className="flex flex-wrap gap-2 text-[10px] font-mono">
              <span className="rounded border border-[#bfe3e0] bg-[#eef7f6] px-2 py-1 text-[#147f79]">{String(restorationData.status || "not_run")}</span>
              {restorationMetrics.elapsed_ms !== undefined && <span className="rounded border border-[#dfd6bf] bg-white px-2 py-1 text-[#586e75]">{String(restorationMetrics.elapsed_ms)} ms</span>}
              <span className="rounded border border-[#d8d3ec] bg-[#f4f1f9] px-2 py-1 text-[#6c71c4]">readability +{String(deobfuscationReadability.improvement || 0)}</span>
            </div>
          </div>
          {asStrings(restorationData.strategy).length > 0 && (
            <div className="mt-3 flex flex-wrap items-center gap-1.5">
              {asStrings(restorationData.strategy).map((stage, index) => (
                <React.Fragment key={`${stage}-${index}`}>
                  {index > 0 && <ChevronRight className="h-3 w-3 text-[#93a1a1]" />}
                  <span className="rounded-full border border-[#dfd6bf] bg-white px-2 py-1 text-[10px] font-mono text-[#586e75]">{stage}</span>
                </React.Fragment>
              ))}
            </div>
          )}
        </section>
      )}

      {deobfuscationFunctions.length > 0 && (
        <section className="rounded-2xl border border-[#d8d3ec] bg-[#fdfaf3] p-4">
          <div className="mb-3 text-xs font-bold text-[#2b3638]">混淆还原前后代码对比</div>
          <div className="space-y-3">
            {deobfuscationFunctions.slice(0, 3).map((item, index) => (
              <div key={`${item.address}-${index}`} className="overflow-hidden rounded-xl border border-[#d8d3ec]">
                <div className="border-b border-[#d8d3ec] bg-[#f4f1f9] px-3 py-2 text-[10px] font-mono text-[#6c71c4]">{String(item.address)} · {asStrings(item.transformations).join(" · ") || "CFG annotation"}</div>
                <div className="grid grid-cols-1 gap-px bg-[#d8d3ec] lg:grid-cols-2">
                  <pre className="max-h-64 overflow-auto whitespace-pre-wrap bg-[#202a2d] p-3 text-[11px] leading-relaxed text-[#cbd5d1]">{String(item.before || "")}</pre>
                  <pre className="max-h-64 overflow-auto whitespace-pre-wrap bg-[#172326] p-3 text-[11px] leading-relaxed text-[#bfe8df]">{String(item.after || "")}</pre>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="rounded-2xl border border-[#dfd6bf] bg-[#fdfaf3] p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs font-bold text-[#2b3638]"><Wrench className="h-4 w-4 text-[#2aa198]" />智能体自主分析计划</div>
          <span className="rounded-full border border-[#bfe3e0] bg-[#eef7f6] px-2 py-1 text-[10px] font-mono text-[#2aa198]">
            AUTHORIZED · {dynamicRecoveryCompleted ? "ISOLATED DYNAMIC" : "STATIC"}
          </span>
        </div>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
          {stages.map((item, index) => {
            const status = String(item.stage) === "independent_verification" && verificationCompleted
              ? "completed"
              : String(item.status || "unknown");
            const complete = status === "completed";
            return (
              <div key={`${item.stage}-${index}`} className={`rounded-xl border p-3 ${complete ? "border-[#cce38d] bg-[#f4f8e6]" : "border-[#dfd6bf] bg-[#f7f1df]"}`}>
                <div className="flex items-center gap-1 text-[10px] font-mono text-[#839496]">{String(index + 1).padStart(2, "0")}<ChevronRight className="h-3 w-3" /></div>
                <div className="mt-1 text-xs font-bold text-[#2b3638]">{STAGE_LABEL[String(item.stage)] || String(item.stage)}</div>
                <div className={`mt-1 text-[10px] font-mono ${complete ? "text-[#859900]" : "text-[#b58900]"}`}>{status}</div>
              </div>
            );
          })}
        </div>
        {toolRuns.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-2">
            {toolRuns.map((run, index) => (
              <span key={`${run.tool}-${index}`} className="inline-flex items-center gap-1 rounded-full border border-[#d4ccb5] bg-white px-2.5 py-1 text-[10px] font-mono text-[#586e75]">
                {run.status === "ok" || run.status === "partial" ? <CheckCircle2 className="h-3 w-3 text-[#859900]" /> : <AlertTriangle className="h-3 w-3 text-[#b58900]" />}
                {String(run.tool)} · {String(run.status)}
              </span>
            ))}
          </div>
        )}
      </section>

      {codeAddresses.length === 0 ? (
        <section className="rounded-2xl border border-[#ecd8a6] bg-[#fbf4e6] p-5 text-sm text-[#7d6500]">
          <div className="flex items-center gap-2 font-bold"><AlertTriangle className="h-4 w-4" />本次未生成可读伪代码</div>
          <p className="mt-2 text-xs leading-relaxed">
            {decisions.authorization_confirmed === false
              ? "本次任务没有确认二进制逆向授权，因此系统只完成结构与壳特征探查，未调用去壳和反编译工具。请从态势大屏重新指定目标并勾选本地分析授权，或从漏洞测试实验室提交。"
              : decisions.reverse_workflow_selected === false
                ? `逆向流水线未选中：${String(decisions.reason || "当前目标不满足执行条件")}。`
                : "结构、壳/混淆信号和工具状态仍已留证。常见原因是样本仍受虚拟化保护、属于托管代码，或反编译器未识别出本地函数；界面不会用模拟代码替代真实产物。"}
          </p>
        </section>
      ) : (
        <section className="grid min-h-[570px] grid-cols-1 gap-4 xl:grid-cols-[260px_minmax(0,1fr)_330px]">
          <div className="rounded-2xl border border-[#dfd6bf] bg-[#fdfaf3] p-3">
            <div className="mb-3 flex items-center gap-2 text-xs font-bold text-[#2b3638]"><FileSearch className="h-4 w-4 text-[#2aa198]" />函数索引</div>
            <div className="relative mb-2">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-[#93a1a1]" />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="函数名 / 地址" className="w-full rounded-lg border border-[#dfd6bf] bg-[#fbf7eb] py-2 pl-8 pr-2 text-xs font-mono outline-none focus:border-[#2aa198]" />
            </div>
            <div className="max-h-[485px] space-y-1 overflow-y-auto pr-1">
              {filteredFunctions.map((item, index) => {
                const address = addressOf(item);
                const active = address === selectedAddress;
                return (
                  <button key={`${address}-${index}`} onClick={() => setSelectedAddress(address)} className={`w-full rounded-lg border px-2.5 py-2 text-left ${active ? "border-[#2aa198] bg-[#eef7f6]" : "border-transparent hover:border-[#dfd6bf] hover:bg-[#fbf7eb]"}`}>
                    <div className="truncate text-xs font-bold text-[#2b3638]">{String(item.name || `function_${index}`)}</div>
                    <div className="mt-0.5 flex justify-between text-[10px] font-mono text-[#839496]"><span>{address}</span><span>{Number(item.size || 0)} B</span></div>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="min-w-0 overflow-hidden rounded-2xl border border-[#34464a] bg-[#172326] text-[#e9f0ed] shadow-sm">
            <div className="flex items-center justify-between border-b border-white/10 bg-[#213034] px-4 py-3">
              <div className="min-w-0">
                <div className="truncate text-xs font-bold">{String(selectedFunction?.name || `func@${selectedAddress}`)}</div>
                <div className="mt-0.5 text-[10px] font-mono text-[#91aaa5]">{selectedAddress} · radare2 pdc · read-only</div>
              </div>
              <span className="rounded border border-cyan-300/20 bg-cyan-300/10 px-2 py-1 text-[10px] font-mono text-cyan-200">PSEUDOCODE</span>
            </div>
            <pre className="max-h-[515px] overflow-auto p-5 text-[12px] leading-6 text-[#d9e7e2] selection:bg-[#2aa198]/40">{selectedCode || "// 该函数没有单独的 pdc 产物，请从左侧选择有伪代码的函数。"}</pre>
          </div>

          <div className="space-y-4">
            <div className="rounded-2xl border border-[#dfd6bf] bg-[#fdfaf3] p-4">
              <div className="flex items-center gap-2 text-xs font-bold text-[#2b3638]"><GitBranch className="h-4 w-4 text-[#6c71c4]" />关联控制流路径</div>
              <div className="mt-3 space-y-2 text-[11px] font-mono">
                <div className="rounded-lg border border-[#d8d3ec] bg-[#f4f1f9] px-3 py-2 text-[#6c71c4]">ENTRY {selectedAddress}</div>
                {selectedEdges.length ? selectedEdges.map((edge) => (
                  <button key={edge} onClick={() => pseudocode[edge] && setSelectedAddress(edge)} className="flex w-full items-center gap-2 rounded-lg border border-[#dfd6bf] bg-[#fbf7eb] px-3 py-2 text-left text-[#586e75] hover:border-[#6c71c4]">
                    <ChevronRight className="h-3 w-3" />{edge}
                  </button>
                )) : <p className="text-xs leading-relaxed text-[#839496]">当前入口未记录直接 CFG 后继；这不等同于函数不可达。</p>}
              </div>
            </div>

            <div className="rounded-2xl border border-[#dfd6bf] bg-[#fdfaf3] p-4">
              <div className="flex items-center gap-2 text-xs font-bold text-[#2b3638]"><Tag className="h-4 w-4 text-[#b58900]" />关键逻辑自动标定</div>
              <div className="mt-3 max-h-[285px] space-y-2 overflow-y-auto pr-1">
                {logicLocations.length ? logicLocations.map((item, index) => (
                  <button key={`${item.category}-${index}`} onClick={() => item.address && setSelectedAddress(String(item.address))} className="w-full rounded-xl border border-[#e5dbc0] bg-[#fbf7eb] p-3 text-left hover:border-[#b58900]">
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-xs font-bold text-[#2b3638]">{CATEGORY_LABEL[String(item.category)] || String(item.category)}</span>
                      <span className="text-[9px] font-mono text-[#b58900]">{Math.round(Number(item.confidence || 0) * 100)}%</span>
                    </div>
                    <div className="mt-1 truncate text-[10px] font-mono text-[#2aa198]">{String(item.function || item.address || item.source)}</div>
                    <p className="mt-1 line-clamp-3 text-[10px] leading-relaxed text-[#586e75]">{String(item.rationale || item.matched || "语义线索")}</p>
                  </button>
                )) : <p className="text-xs leading-relaxed text-[#839496]">未观察到认证、加解密或注册关键词。此结果表示“未命中规则”，不是安全结论。</p>}
              </div>
            </div>
          </div>
        </section>
      )}

      {(decodedStrings.length > 0 || obfuscationEvidence) && (
        <section className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-2xl border border-[#dfd6bf] bg-[#fdfaf3] p-4">
            <div className="text-xs font-bold text-[#2b3638]">解混淆辅助结果</div>
            <p className="mt-1 text-[11px] text-[#839496]">确定性还原可打印 Base64/十六进制字符串，不执行样本。</p>
            <div className="mt-3 max-h-44 space-y-2 overflow-auto">
              {decodedStrings.length ? decodedStrings.map((item, index) => (
                <div key={index} className="rounded-lg border border-[#dfd6bf] bg-[#fbf7eb] p-2 text-[10px] font-mono">
                  <span className="text-[#b58900]">{String(item.encoding)}</span><span className="mx-2 text-[#93a1a1]">→</span><span className="text-[#2aa198]">{String(item.decoded)}</span>
                </div>
              )) : <div className="text-xs text-[#839496]">未发现可安全确定性还原的编码字符串。</div>}
            </div>
          </div>
          <div className="rounded-2xl border border-[#dfd6bf] bg-[#fdfaf3] p-4">
            <div className="text-xs font-bold text-[#2b3638]">壳 / 混淆判定依据</div>
            <div className="mt-3 flex items-end gap-3"><span className="text-3xl font-black text-[#b58900]">{Number(obfuscationEvidence?.data?.score || 0).toFixed(2)}</span><span className="pb-1 text-[10px] font-mono text-[#839496]">HEURISTIC SCORE</span></div>
            <div className="mt-3 flex flex-wrap gap-2">
              {signalItems.slice(0, 8).map((item, index) => {
                const code = signalCode(item);
                const details = signalEvidence(item);
                return (
                  <span key={`${code}-${index}`} title={details.join(" · ")} className="rounded-full border border-[#ecd8a6] bg-[#fbf4e6] px-2 py-1 text-[10px] text-[#7d6500]">
                    {protectionMethodLabel(code)}{details.length ? ` · ${details.join(" / ")}` : ""}
                  </span>
                );
              })}
            </div>
          </div>
        </section>
      )}
    </div>
  );
};
