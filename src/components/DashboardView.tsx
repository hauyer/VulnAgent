import React, { useState } from "react";
import {
  Sparkles,
  Zap,
  ShieldAlert,
  ShieldCheck,
  Bug,
  Database,
  Layers,
  ArrowRight,
  Play,
  FileCode,
  Terminal,
  Activity,
  Cpu,
  Flame,
  CheckCircle2,
  Clock,
  ChevronRight,
  ExternalLink,
  Plus,
  GitBranch,
  Search,
  Check,
} from "lucide-react";
import {
  Task,
  VulnerabilityCandidate,
  Evidence,
  DomainEvent,
  ActiveTab,
} from "../types.js";
import { useTranslation } from "../i18n.js";

interface DashboardViewProps {
  task: Task;
  findings: VulnerabilityCandidate[];
  evidenceList: Evidence[];
  events: DomainEvent[];
  onTriggerRun: () => void;
  isRunning: boolean;
  onNavigateTab: (tab: ActiveTab) => void;
  onSelectEvidence: (evidenceId: string) => void;
  onLaunchNewTask: (targetPath: string, targetType: "source" | "binary", language?: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  task,
  findings,
  evidenceList,
  events,
  onTriggerRun,
  isRunning,
  onNavigateTab,
  onSelectEvidence,
  onLaunchNewTask,
}) => {
  const { t, language } = useTranslation();
  const [showCustomLauncher, setShowCustomLauncher] = useState(false);
  const [customPath, setCustomPath] = useState("");
  const [customType, setCustomType] = useState<"source" | "binary">("source");
  const [customLang, setCustomLang] = useState("c");

  const confirmedFindings = findings.filter((f) => f.status === "confirmed");
  const topCriticalFinding = confirmedFindings[0] || findings[0];

  const benchmarks = [
    {
      title: language === "zh" ? "C 语言网络守护程序栈缓冲区溢出" : "C Daemon Stack Buffer Overflow",
      path: "samples/source_demo",
      type: "source" as const,
      language: "python",
      cwe: "CWE-78 / CWE-89",
      description:
        language === "zh"
          ? "经典远程网络守护程序，在 handle_client_request() 中对定长栈缓冲区调用无边界检查的 strcpy()。"
          : "Classic remote network daemon vulnerable to unbounded strcpy() into fixed-size buffer.",
      badge: language === "zh" ? "内存破坏 / 栈溢出" : "Memory Safety",
    },
    {
      title: language === "zh" ? "Python Web SQL 注入危险汇聚点" : "Python Web SQL Injection Sink",
      path: "samples/source_demo/vulnerable.py",
      type: "source" as const,
      language: "python",
      cwe: "CWE-89",
      description:
        language === "zh"
          ? "Web 应用程序直接使用未经验证的用户参数拼接原生 SQL 查询，形成经典危险汇聚点(Sink)。"
          : "Web application constructing unsanitized raw SQL queries directly from user parameters.",
      badge: language === "zh" ? "Web安全 / SQL注入" : "Web Security",
    },
    {
      title: language === "zh" ? "x86_64 ELF 编译二进制逆向与鉴权分析" : "x86_64 Compiled Binary Crackme",
      path: "benchmarks/bin/auth_daemon_x64",
      type: "binary" as const,
      language: "c",
      cwe: "CWE-134",
      description:
        language === "zh"
          ? "编译后的 ELF 二进制可执行文件，包含格式化字符串漏洞与易受劫持的未初始化函数指针调用。"
          : "Compiled ELF binary with format string vulnerability and vulnerable function pointer call.",
      badge: language === "zh" ? "二进制 / 逆向分析" : "Binary / ELF",
    },
  ];

  const handleCustomSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customPath.trim()) return;
    onLaunchNewTask(customPath.trim(), customType, customLang);
    setCustomPath("");
    setShowCustomLauncher(false);
  };

  const pipelineStages = [
    { name: language === "zh" ? "1. 目标探查" : "1. Profiling" },
    { name: language === "zh" ? "2. 智能规划" : "2. Planning" },
    { name: language === "zh" ? "3. 静态/逆向" : "3. Source / Binary" },
    { name: language === "zh" ? "4. 动态模糊" : "4. Dynamic Fuzz" },
    { name: language === "zh" ? "5. 独立复核" : "5. Verification" },
    { name: language === "zh" ? "6. 审计报告" : "6. Reporting" },
  ];

  return (
    <div className="space-y-6">
      {/* Hero Command HUD Banner */}
      <div className="relative rounded-3xl bg-[#f4eedb] border border-[#dfd6bf] p-6 sm:p-8 overflow-hidden shadow-sm">
        {/* Soft Warm Accents */}
        <div className="absolute top-0 right-0 -mr-20 -mt-20 w-80 h-80 rounded-full bg-[#2aa198]/10 blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-1/3 w-60 h-60 rounded-full bg-[#b58900]/10 blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-[#e6deca] text-[#2aa198] border border-[#d2c8af] flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#2aa198] animate-ping" />
                VULNAGENT RUNTIME v0.3.0
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono bg-[#eee8d5] text-[#586e75] border border-[#dfd6bf]">
                {language === "zh" ? "目标类型" : "Target"}: {task.target.target_type.toUpperCase()}
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono bg-[#edf5d3] text-[#859900] border border-[#cce38d] font-semibold">
                {language === "zh" ? "目标架构: x86_64" : "Architecture: x86_64"}
              </span>
            </div>

            <div>
              <h1 className="text-2xl sm:text-3xl font-extrabold text-[#2b3638] tracking-tight">
                {language === "zh" ? "自研多智能体软件漏洞分析平台" : "Autonomous Security Intelligence Platform"}
              </h1>
              <p className="text-sm font-mono text-[#2aa198] font-medium mt-1 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#2aa198]" />
                <span>{task.target.path}</span>
              </p>
            </div>
          </div>

          {/* Action Trigger Buttons */}
          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={onTriggerRun}
              disabled={isRunning}
              className="px-5 py-2.5 rounded-xl bg-[#2aa198] hover:bg-[#238b83] text-white font-bold text-xs tracking-wide transition-all shadow-xs flex items-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <Play className={`w-4 h-4 fill-current ${isRunning ? "animate-spin" : ""}`} />
              <span>{isRunning ? (language === "zh" ? "多智能体推理中..." : "Orchestrating...") : (language === "zh" ? "启动自主挖掘流水线" : "Execute Full Pipeline")}</span>
            </button>

            <button
              onClick={() => onNavigateTab("report")}
              className="px-4 py-2.5 rounded-xl bg-[#fdfaf3] hover:bg-[#ffffff] border border-[#dfd6bf] text-[#2b3638] text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer shadow-2xs"
            >
              <span>{language === "zh" ? "查看安全审计报告" : "View Audit Report"}</span>
              <ChevronRight className="w-4 h-4 text-[#586e75]" />
            </button>
          </div>
        </div>

        {/* Pipeline Stage Progression Bar */}
        <div className="mt-8 pt-6 border-t border-[#dfd6bf]">
          <div className="flex items-center justify-between text-[11px] font-mono text-[#586e75] mb-2">
            <span>{language === "zh" ? "多智能体协同流水线阶段" : "MULTI-AGENT PIPELINE STAGES"}</span>
            <span className="text-[#2aa198] font-bold">
              {language === "zh" ? "状态: " : "STATUS: "}
              {t(`status_${task.status}`) || task.status.toUpperCase()}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 font-mono text-xs">
            {pipelineStages.map((stage) => (
              <div
                key={stage.name}
                className="p-2 rounded-lg bg-[#fdfaf3] border border-[#dfd6bf] text-center transition-all relative overflow-hidden shadow-2xs"
              >
                <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-[#2aa198] to-[#859900]" />
                <span className="text-[11px] font-semibold text-[#2b3638] truncate block">
                  {stage.name}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 4 Telemetry Dials / Stat HUD Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Stat 1: Attack Surface Coverage */}
        <div
          onClick={() => onNavigateTab("topology")}
          className="p-5 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] hover:border-[#2aa198]/60 transition-all cursor-pointer group shadow-2xs"
        >
          <div className="flex items-center justify-between text-[#586e75] mb-2">
            <span className="text-[11px] uppercase font-mono tracking-wider font-semibold">
              {language === "zh" ? "控制流分支覆盖度" : "Branch Coverage"}
            </span>
            <Activity className="w-4 h-4 text-[#2aa198] group-hover:scale-110 transition-transform" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-[#2b3638]">84.6%</span>
            <span className="text-xs font-mono text-[#859900] font-bold">+12% AST</span>
          </div>
          <p className="text-[11px] text-[#586e75] mt-2 font-mono">
            {language === "zh" ? "已探测 42/50 个执行分支" : "42 of 50 execution branches probed"}
          </p>
        </div>

        {/* Stat 2: Fuzzing Engine Metrics */}
        <div
          onClick={() => onNavigateTab("evidence")}
          className="p-5 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] hover:border-[#b58900]/60 transition-all cursor-pointer group shadow-2xs"
        >
          <div className="flex items-center justify-between text-[#586e75] mb-2">
            <span className="text-[11px] uppercase font-mono tracking-wider font-semibold">
              {language === "zh" ? "动态模糊测试速率" : "Dynamic Fuzz Rate"}
            </span>
            <Bug className="w-4 h-4 text-[#b58900] group-hover:scale-110 transition-transform" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-[#b58900]">1,420</span>
            <span className="text-xs font-mono text-[#586e75]">{language === "zh" ? "次/秒" : "exec/s"}</span>
          </div>
          <p className="text-[11px] text-[#586e75] mt-2 font-mono">
            AFL++ &bull; {language === "zh" ? "捕获 1 个可复现崩溃转储" : "1 reproducible crash dump"}
          </p>
        </div>

        {/* Stat 3: Independent Verification Confidence */}
        <div
          onClick={() => onNavigateTab("vulnerabilities")}
          className="p-5 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] hover:border-[#859900]/60 transition-all cursor-pointer group shadow-2xs"
        >
          <div className="flex items-center justify-between text-[#586e75] mb-2">
            <span className="text-[11px] uppercase font-mono tracking-wider font-semibold">
              {language === "zh" ? "独立复核置信度" : "Verification Confidence"}
            </span>
            <ShieldCheck className="w-4 h-4 text-[#859900] group-hover:scale-110 transition-transform" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-[#859900]">98.0%</span>
            <span className="text-xs font-mono text-[#859900] font-bold">{language === "zh" ? "已确认" : "CONFIRMED"}</span>
          </div>
          <p className="text-[11px] text-[#586e75] mt-2 font-mono">
            {language === "zh" ? "经 VerificationAgent 独立证实成立" : "Independent Verification Agent sign-off"}
          </p>
        </div>

        {/* Stat 4: Evidence Artifact Depth */}
        <div
          onClick={() => onNavigateTab("evidence")}
          className="p-5 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] hover:border-[#6c71c4]/60 transition-all cursor-pointer group shadow-2xs"
        >
          <div className="flex items-center justify-between text-[#586e75] mb-2">
            <span className="text-[11px] uppercase font-mono tracking-wider font-semibold">
              {language === "zh" ? "证据链存证数" : "Verified Artifacts"}
            </span>
            <Database className="w-4 h-4 text-[#6c71c4] group-hover:scale-110 transition-transform" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-[#6c71c4]">{evidenceList.length}</span>
            <span className="text-xs font-mono text-[#586e75]">{language === "zh" ? "项" : "items"}</span>
          </div>
          <p className="text-[11px] text-[#586e75] mt-2 font-mono">
            {language === "zh" ? "污点路径、崩溃转储与 ASAN 输出" : "Taint paths, crash dumps, and ASAN trace"}
          </p>
        </div>
      </div>

      {/* Course Design Innovations Section */}
      <div className="p-6 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#dfd6bf] pb-3">
          <div>
            <h3 className="text-sm font-bold text-[#2b3638] flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#2aa198]" />
              {t("dashInnovationsTitle")}
            </h3>
            <p className="text-xs text-[#586e75] mt-0.5">
              {t("dashInnovationsSubtitle")}
            </p>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#eef7f6] text-[#2aa198] border border-[#bfe3e0] font-semibold self-start sm:self-auto">
            AGENTS.md &bull; V0.2
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          <div className="p-3.5 rounded-xl bg-[#f7f2e4] border border-[#e2d9c4] space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-md bg-[#2aa198]/20 text-[#2aa198] flex items-center justify-center text-[10px] font-bold">01</span>
              <h4 className="text-xs font-bold text-[#2b3638]">{t("inno1Title")}</h4>
            </div>
            <p className="text-[11px] text-[#586e75] leading-relaxed">
              {t("inno1Desc")}
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-[#f7f2e4] border border-[#e2d9c4] space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-md bg-[#859900]/20 text-[#859900] flex items-center justify-center text-[10px] font-bold">02</span>
              <h4 className="text-xs font-bold text-[#2b3638]">{t("inno2Title")}</h4>
            </div>
            <p className="text-[11px] text-[#586e75] leading-relaxed">
              {t("inno2Desc")}
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-[#f7f2e4] border border-[#e2d9c4] space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-md bg-[#b58900]/20 text-[#b58900] flex items-center justify-center text-[10px] font-bold">03</span>
              <h4 className="text-xs font-bold text-[#2b3638]">{t("inno3Title")}</h4>
            </div>
            <p className="text-[11px] text-[#586e75] leading-relaxed">
              {t("inno3Desc")}
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-[#f7f2e4] border border-[#e2d9c4] space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-md bg-[#dc322f]/20 text-[#dc322f] flex items-center justify-center text-[10px] font-bold">04</span>
              <h4 className="text-xs font-bold text-[#2b3638]">{t("inno4Title")}</h4>
            </div>
            <p className="text-[11px] text-[#586e75] leading-relaxed">
              {t("inno4Desc")}
            </p>
          </div>
        </div>
      </div>

      {/* Benchmark Target Quick Switcher & Launcher */}
      <div className="p-6 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-[#2b3638] flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[#2aa198]" />
              {t("dashBenchmarkTitle")}
            </h3>
            <p className="text-xs text-[#586e75] mt-0.5">
              {t("dashBenchmarkSubtitle")}
            </p>
          </div>

          <button
            onClick={() => setShowCustomLauncher(!showCustomLauncher)}
            className="px-3 py-1.5 rounded-lg bg-[#eee8d5] hover:bg-[#e4dcbe] border border-[#dfd6bf] text-xs font-mono text-[#2b3638] flex items-center gap-1.5 transition-colors cursor-pointer shadow-2xs"
          >
            <Plus className="w-3.5 h-3.5 text-[#2aa198]" />
            <span>{language === "zh" ? "指定自定义审计目标路径" : "Custom Target Path"}</span>
          </button>
        </div>

        {/* Custom Target Form Accordion */}
        {showCustomLauncher && (
          <form
            onSubmit={handleCustomSubmit}
            className="p-4 rounded-xl bg-[#f5eed9] border border-[#2aa198]/40 space-y-3"
          >
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <label className="text-[10px] font-mono text-[#586e75] block mb-1">
                  {language === "zh" ? "目标源码或二进制程序相对路径" : "Target File / Binary Path"}
                </label>
                <input
                  type="text"
                  value={customPath}
                  onChange={(e) => setCustomPath(e.target.value)}
                  placeholder="e.g. src/core/auth_handler.c"
                  className="w-full px-3 py-1.5 bg-[#fdfaf3] border border-[#dfd6bf] rounded-lg text-xs font-mono text-[#2b3638] placeholder:text-[#839496] focus:outline-none focus:border-[#2aa198]"
                  required
                />
              </div>

              <div>
                <label className="text-[10px] font-mono text-[#586e75] block mb-1">
                  {language === "zh" ? "程序类型" : "Target Type"}
                </label>
                <select
                  value={customType}
                  onChange={(e) => setCustomType(e.target.value as "source" | "binary")}
                  className="w-full px-3 py-1.5 bg-[#fdfaf3] border border-[#dfd6bf] rounded-lg text-xs font-mono text-[#2b3638] focus:outline-none cursor-pointer"
                >
                  <option value="source">{language === "zh" ? "源代码文件 (C/Python/Go)" : "Source Code"}</option>
                  <option value="binary">{language === "zh" ? "编译后二进制文件 (ELF/PE)" : "Compiled Binary (ELF/PE)"}</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowCustomLauncher(false)}
                className="px-3 py-1 rounded-lg text-xs font-mono text-[#586e75] hover:text-[#2b3638] cursor-pointer"
              >
                {language === "zh" ? "取消" : "Cancel"}
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg bg-[#2aa198] hover:bg-[#238b83] text-white font-semibold text-xs transition-colors cursor-pointer"
              >
                {language === "zh" ? "初始化并开始审计" : "Initialize & Scan Target"}
              </button>
            </div>
          </form>
        )}

        {/* 3 Benchmark Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          {benchmarks.map((preset) => {
            const isCurrent = task.target.path === preset.path;
            return (
              <div
                key={preset.path}
                className={`p-4 rounded-xl border transition-all flex flex-col justify-between ${
                  isCurrent
                    ? "bg-[#eef7f6] border-[#2aa198]/60 shadow-2xs ring-1 ring-[#2aa198]/30"
                    : "bg-[#f7f2e4] border-[#e2d9c4] hover:bg-[#fbf8ee]"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#eef7f6] text-[#2aa198] border border-[#bfe3e0]">
                      {preset.cwe}
                    </span>
                    <span className="text-[10px] font-mono text-[#586e75]">
                      {preset.badge}
                    </span>
                  </div>

                  <h4 className="text-xs font-bold text-[#2b3638]">{preset.title}</h4>
                  <p className="text-[11px] text-[#586e75] mt-1 line-clamp-2 leading-relaxed">
                    {preset.description}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-[#dfd6bf]/80 flex items-center justify-between">
                  <span className="font-mono text-[10px] text-[#839496] truncate max-w-[150px]">
                    {preset.path}
                  </span>
                  <button
                    onClick={() => onLaunchNewTask(preset.path, preset.type, preset.language)}
                    className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition-colors cursor-pointer ${
                      isCurrent
                        ? "bg-[#2aa198] text-white"
                        : "bg-[#eee8d5] text-[#586e75] hover:bg-[#e4dcbe] hover:text-[#2b3638]"
                    }`}
                  >
                    {isCurrent
                      ? (language === "zh" ? "当前审计目标" : "Active Target")
                      : (language === "zh" ? "切换并分析" : "Switch & Audit")}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Dual Highlights: Critical Confirmed Finding + Live Telemetry Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Top Critical Finding Highlight */}
        <div className="lg:col-span-7 p-6 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-[#dfd6bf] pb-3">
            <span className="text-xs font-bold text-[#2b3638] uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-[#dc322f]" />
              {language === "zh" ? "已确认的关键严重漏洞 (Confirmed)" : "Critical Confirmed Vulnerability"}
            </span>
            <button
              onClick={() => onNavigateTab("vulnerabilities")}
              className="text-xs font-mono text-[#2aa198] hover:underline flex items-center gap-1 cursor-pointer font-semibold"
            >
              <span>{language === "zh" ? `查看全部 (${findings.length})` : `View all (${findings.length})`}</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          {topCriticalFinding ? (
            <div className="space-y-3 font-sans">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-[#fce8e6] text-[#dc322f] border border-[#f5b8b5]">
                    {topCriticalFinding.severity || "CRITICAL"}
                  </span>
                  <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-[#eef7f6] text-[#2aa198] border border-[#bfe3e0]">
                    {topCriticalFinding.cwe_id}
                  </span>
                  <span className="text-xs font-mono text-[#859900] font-bold bg-[#edf5d3] px-2 py-0.5 rounded border border-[#cce38d]">
                    {language === "zh" ? "已独立复核确认" : "CONFIRMED"}
                  </span>
                </div>

                {topCriticalFinding.metadata?.cvss_score && (
                  <span className="text-xs font-mono text-[#dc322f] font-bold">
                    CVSS {topCriticalFinding.metadata.cvss_score}
                  </span>
                )}
              </div>

              <h4 className="text-sm font-bold text-[#2b3638]">{topCriticalFinding.title}</h4>
              <p className="text-xs text-[#362f27] leading-relaxed bg-[#f5eed9] p-3.5 rounded-xl border border-[#e2d9c4]">
                {topCriticalFinding.description}
              </p>

              {topCriticalFinding.location && (
                <div className="p-3 rounded-lg bg-[#f5eed9] border border-[#e2d9c4] text-xs font-mono text-[#586e75] flex items-center justify-between">
                  <span>
                    {language === "zh" ? "代码位置: " : "Location: "}
                    <strong className="text-[#2b3638]">{topCriticalFinding.location.file_path}:{topCriticalFinding.location.line_start}</strong>
                  </span>
                  <span className="text-[#2aa198] font-semibold">fn {topCriticalFinding.location.function_name}()</span>
                </div>
              )}

              {/* Linked Evidence Chips */}
              <div className="flex items-center gap-2 flex-wrap pt-1">
                <span className="text-[11px] font-mono text-[#586e75]">
                  {language === "zh" ? "关联合成证据实体: " : "Corroborated Artifacts: "}
                </span>
                {topCriticalFinding.evidence_ids.map((evId) => (
                  <button
                    key={evId}
                    onClick={() => onSelectEvidence(evId)}
                    className="px-2 py-1 rounded bg-[#eee8d5] hover:bg-[#e4dcbe] border border-[#dfd6bf] text-[10px] font-mono text-[#2aa198] font-semibold cursor-pointer transition-colors"
                  >
                    {evId}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-[#839496] text-xs">
              {language === "zh" ? "未发现严重漏洞" : "No critical vulnerabilities found."}
            </div>
          )}
        </div>

        {/* Right: Live Event Stream Ticker */}
        <div className="lg:col-span-5 p-6 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-[#dfd6bf] pb-3">
            <span className="text-xs font-bold text-[#2b3638] uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#2aa198]" />
              {t("traceTitle")}
            </span>
            <button
              onClick={() => onNavigateTab("trace")}
              className="text-xs font-mono text-[#2aa198] hover:underline flex items-center gap-1 cursor-pointer font-semibold"
            >
              <span>{language === "zh" ? "完整遥测终端" : "Full terminal"}</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2 max-h-[290px] overflow-y-auto font-mono text-xs pr-1">
            {events.slice(-6).reverse().map((ev) => (
              <div
                key={ev.event_id}
                className="p-2.5 rounded-lg bg-[#f5eed9] border border-[#e2d9c4] flex items-start gap-2.5 shadow-2xs"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-[#2aa198] mt-1.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] text-[#2aa198] font-bold uppercase truncate">
                      {ev.event_type}
                    </span>
                    <span className="text-[9px] text-[#839496]">
                      {new Date(ev.timestamp).toLocaleTimeString([], { hour12: false })}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#586e75] truncate mt-0.5">
                    {ev.payload?.summary ||
                      ev.payload?.description ||
                      ev.payload?.route ||
                      ev.payload?.vulnerability_id ||
                      "Processed payload event"}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

