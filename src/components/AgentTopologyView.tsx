import React, { useState } from "react";
import {
  Layers,
  Cpu,
  ShieldAlert,
  Binary,
  FolderCode,
  Bug,
  ShieldCheck,
  FileText,
  Activity,
  CheckCircle2,
  Clock,
  ArrowRight,
  Info,
  Terminal,
  Zap,
} from "lucide-react";
import { AgentNodeInfo, Task, DomainEvent } from "../types.js";
import { useTranslation } from "../i18n.js";

interface AgentTopologyViewProps {
  task: Task;
  events: DomainEvent[];
  onTriggerRun: () => void;
  isRunning: boolean;
}

export const AgentTopologyView: React.FC<AgentTopologyViewProps> = ({
  task,
  events,
  onTriggerRun,
  isRunning,
}) => {
  const { t, language } = useTranslation();

  const AGENT_NODES: AgentNodeInfo[] = [
    {
      id: "orchestrator",
      name: language === "zh" ? "Supervisor 状态机调度器" : "Supervisor / Orchestrator",
      role: language === "zh" ? "状态机调度与有限有界路由" : "State Machine & Runtime Router",
      module: "src/vulnagent/agent_runtime/supervisor.py",
      category: "orchestration",
      status: "completed",
      description:
        language === "zh"
          ? "负责驱动 LangGraph DAG 状态图流转。内置最大步数（上限10步）防死循环保护与确定性回退机制，统管全局 AgentMessage 消息派发。"
          : "Orchestrates state transitions across LangGraph DAG. Enforces step limits (max 10) and deterministic fallback.",
      inputContract: ["Task", "TargetConfig"],
      outputContract: ["RuntimeState", "AgentRouteCommand"],
      evidenceTypesProduced: [],
    },
    {
      id: "planner_agent",
      name: language === "zh" ? "Planner 规划智能体" : "Planner Agent",
      role: language === "zh" ? "程序语义理解与攻击面探测规划" : "Program Understanding & Attack Surface Planner",
      module: "src/vulnagent/agents/planner_agent.py",
      category: "orchestration",
      status: "completed",
      description:
        language === "zh"
          ? "解析目标代码格式、编程语言与底层架构，自动构建 AST 符号探测策略与动态测试路线图。"
          : "Parses target format, identifies language/architecture, and synthesizes dynamic execution plan.",
      inputContract: ["Target", "Metadata"],
      outputContract: ["ExecutionPlan", "DomainEvent"],
      evidenceTypesProduced: ["model_reasoning_summary"],
    },
    {
      id: "source_audit_agent",
      name: language === "zh" ? "Source Audit 源码审计智能体" : "Source Audit Agent",
      role: language === "zh" ? "静态 AST/CFG 污点分析与危险 API 扫描" : "Static Code & AST/Taint Analyzer",
      module: "src/vulnagent/analyzers/source/audit_agent.py",
      category: "analysis",
      status: "completed",
      description:
        language === "zh"
          ? "计算跨过程函数调用图与数据流，针对 strcpy、system、sprintf 等危险 API 提取 Source-to-Sink 污点路径，生成 CANDIDATE 候选漏洞。"
          : "Evaluates AST, Call Graphs, Dangerous C/Python APIs, and computes inter-procedural taint flow paths.",
      inputContract: ["SourceFiles", "LanguageGrammar"],
      outputContract: ["VulnerabilityCandidate(status=CANDIDATE)", "Evidence"],
      evidenceTypesProduced: ["source_location", "code_snippet", "taint_path"],
    },
    {
      id: "binary_analysis_agent",
      name: language === "zh" ? "Binary Analysis 二进制逆向智能体" : "Binary Analysis Agent",
      role: language === "zh" ? "反汇编反编译与 ELF/PE 符号探测" : "Disassembly & ELF/PE Symbolic Inspector",
      module: "src/vulnagent/analyzers/binary/binary_agent.py",
      category: "analysis",
      status: "idle",
      description:
        language === "zh"
          ? "提取 ELF/PE 段节区、导入表、字符串常量，重构控制流图 (CFG) 与汇编指令序列，定位格式化字符串与函数指针劫持。"
          : "Extracts sections, strings, functions, CFG, and disassembly instructions from compiled binaries.",
      inputContract: ["BinaryExecutable", "Architecture"],
      outputContract: ["VulnerabilityCandidate(status=CANDIDATE)", "Evidence"],
      evidenceTypesProduced: ["binary_address", "disassembly", "cfg_path"],
    },
    {
      id: "fuzz_agent",
      name: language === "zh" ? "Fuzz 模糊测试智能体" : "Fuzz Agent",
      role: language === "zh" ? "动态变异测试与 Crash 崩溃捕获" : "Dynamic Seed Mutation & Crash Hunter",
      module: "src/vulnagent/fuzz/fuzz_agent.py",
      category: "testing",
      status: "completed",
      description:
        language === "zh"
          ? "根据静态危险点生成确定性引导输入，在固定预算和本地授权边界内执行受控变异，记录运行轨迹与去重崩溃指纹。"
          : "Generates deterministic guidance from static risks and performs fixed-budget controlled mutations with runtime traces and deduplicated crash fingerprints.",
      inputContract: ["SeedCorpus", "RiskHints", "SandboxPolicy"],
      outputContract: ["Evidence(runtime_trace)", "Evidence(crash_log)"],
      evidenceTypesProduced: ["fuzz_input", "runtime_trace", "crash_log", "tool_result"],
    },
    {
      id: "verification_agent",
      name: language === "zh" ? "Verification 独立复核智能体" : "Verification Agent",
      role: language === "zh" ? "独立漏洞仲裁复核（CONFIRMED 唯一写入者）" : "Independent Verifier (Sole Confirmer)",
      module: "src/vulnagent/verification/verification_agent.py",
      category: "verification",
      status: "completed",
      description:
        language === "zh"
          ? "核心设计：发现与验证解耦！基于严谨证据链交叉检验漏洞成立性，是全系统中唯一有权将漏洞状态置为 CONFIRMED 或 REJECTED 的智能体。"
          : "CRITICAL: Independent verification decouples detection from confirmation. The sole agent authorized to set CONFIRMED.",
      inputContract: ["VulnerabilityCandidate", "EvidenceChain"],
      outputContract: ["VulnerabilityCandidate(status=CONFIRMED/REJECTED)", "VerificationResult"],
      evidenceTypesProduced: ["verification_result"],
    },
    {
      id: "reviewer_agent",
      name: language === "zh" ? "Reviewer 二次仲裁智能体" : "Reviewer Agent",
      role: language === "zh" ? "误报过滤与冲突消解" : "False-Positive Eliminator & Peer Review",
      module: "src/vulnagent/verification/reviewer_agent.py",
      category: "verification",
      status: "completed",
      description:
        language === "zh"
          ? "对处于 UNCERTAIN 不确定状态或静态与动态结果产生冲突的漏洞进行同业复审，有效消除大模型虚构幻觉与误报警报。"
          : "Performs secondary review on uncertain or conflicting candidates to prevent false alarms.",
      inputContract: ["VulnerabilityCandidate(UNCERTAIN)", "Context"],
      outputContract: ["ReviewAssessment", "DomainEvent"],
      evidenceTypesProduced: ["model_reasoning_summary"],
    },
    {
      id: "report_agent",
      name: language === "zh" ? "Report 报告合成智能体" : "Report Agent",
      role: language === "zh" ? "全维度安全情报汇聚与修复建议生成" : "Vulnerability Synthesizer & Security Intelligence",
      module: "src/vulnagent/agents/report_agent.py",
      category: "reporting",
      status: "completed",
      description:
        language === "zh"
          ? "消费最终 Task、ConfirmedFindings 与 EvidenceMatrix，生成包含 CVSS 评分、漏洞机理与具体修复补丁的代码审计报告。"
          : "Aggregates confirmed vulnerabilities, evidence chains, and produces structured remediation recommendations.",
      inputContract: ["Task", "ConfirmedFindings", "EvidenceMatrix"],
      outputContract: ["ReportResult", "RemediationRoadmap"],
      evidenceTypesProduced: [],
    },
    {
      id: "program_restoration_agent",
      name: language === "zh" ? "Program Restoration 程序还原智能体" : "Program Restoration Agent",
      role: language === "zh" ? "保护识别、内存映像与 PE/DEX 结构修复" : "Protection Classification & Structure Recovery",
      module: "src/vulnagent/agents/program_restoration_agent.py",
      category: "analysis",
      status: "completed",
      description:
        language === "zh"
          ? "融合节区、熵、入口点与导入特征，自主选择静态副本去壳或隔离动态快照；重建 IAT/PE 结构后必须通过解析器校验。"
          : "Fuses section, entropy, entry-point and import evidence, selects a bounded strategy, and validates rebuilt PE/DEX artifacts.",
      inputContract: ["AuthorizedBinary", "ProtectionPolicy"],
      outputContract: ["RestorationEvidence", "ValidatedArtifact"],
      evidenceTypesProduced: ["tool_result"],
    },
    {
      id: "code_deobfuscation_agent",
      name: language === "zh" ? "Code Deobfuscation 混淆还原智能体" : "Code Deobfuscation Agent",
      role: language === "zh" ? "OLLVM 四类模式还原与语义可读性增强" : "OLLVM Recovery & Semantic Readability",
      module: "src/vulnagent/agents/code_deobfuscation_agent.py",
      category: "analysis",
      status: "completed",
      description:
        language === "zh"
          ? "检测控制流平坦化、虚假控制流、指令替换和字符串加密，保留前后对比；大模型只做辅助业务语义标注，不修改可执行字节。"
          : "Recovers four OLLVM pattern families, preserves before/after evidence, and limits the LLM to auxiliary annotations.",
      inputContract: ["BinaryAnalysisResult", "RuntimeTrace"],
      outputContract: ["RecoveredCFG", "ReadabilityAssessment"],
      evidenceTypesProduced: ["tool_result", "model_reasoning_summary"],
    },
  ];

  const [selectedAgent, setSelectedAgent] = useState<AgentNodeInfo>(AGENT_NODES[0]);

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-[#f4eedb] border border-[#dfd6bf] shadow-sm">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-6 h-6 rounded-lg bg-[#2aa198]/10 border border-[#2aa198]/30 flex items-center justify-center text-[#2aa198]">
              <Layers className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-base font-bold text-[#2b3638]">{t("topoTitle")}</h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#e6deca] text-[#2aa198] border border-[#d2c8af] font-semibold">
              LangGraph DAG
            </span>
          </div>
          <p className="text-xs text-[#586e75]">
            {t("topoSubtitle")}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-3 py-1.5 rounded-lg bg-[#fdfaf3] border border-[#dfd6bf] text-xs font-mono text-[#586e75] flex items-center gap-2 shadow-2xs">
            <span className="w-2 h-2 rounded-full bg-[#859900] animate-pulse" />
            <span>
              {language === "zh" ? "流水线状态: " : "State: "}
              <strong className="text-[#2b3638]">{t(`status_${task.status}`) || task.status.toUpperCase()}</strong>
            </span>
          </div>
          <button
            onClick={onTriggerRun}
            disabled={isRunning || task.status !== "created"}
            className="px-4 py-2 rounded-lg bg-[#2aa198] hover:bg-[#238b83] text-white font-semibold text-xs transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-xs"
          >
            <Zap className="w-3.5 h-3.5 fill-current" />
            <span>
              {isRunning
                ? (language === "zh" ? "执行中..." : "Executing...")
                : task.status !== "created"
                  ? (language === "zh" ? "本次协同已完成" : "DAG Run Complete")
                  : (language === "zh" ? "触发 DAG 协同" : "Trigger DAG Pipeline")}
            </span>
          </button>
        </div>
      </div>

      {/* Main Grid: SVG DAG Canvas + Agent Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Interactive Topology Canvas */}
        <div className="lg:col-span-8 p-6 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] relative overflow-hidden shadow-sm">
          {/* Subtle Grid Backdrop */}
          <div className="absolute inset-0 bg-cyber-grid opacity-30 pointer-events-none" />
          
          <div className="flex items-center justify-between mb-4 relative z-10">
            <span className="text-[11px] font-semibold text-[#586e75] uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-[#2aa198]" />
              {language === "zh" ? "实时执行状态图拓扑" : "Live Execution Graph"}
            </span>
            <span className="text-[10px] font-mono text-[#839496]">
              {language === "zh" ? "点击任意节点查看契约定义与交互规则" : "Click node to inspect contract & schema"}
            </span>
          </div>

          {/* SVG Pipeline Canvas */}
          <div className="relative z-10 py-4">
            {/* Flow Stage 1: Supervisor */}
            <div className="flex justify-center mb-8">
              <button
                onClick={() => setSelectedAgent(AGENT_NODES[0])}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer w-72 text-left relative ${
                  selectedAgent.id === "orchestrator"
                    ? "bg-[#eef7f6] border-[#2aa198] ring-2 ring-[#2aa198]/20 shadow-sm"
                    : "bg-[#fcf8ed] border-[#dfd6bf] hover:border-[#cbbea2]"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[10px] font-mono text-[#2aa198] uppercase font-bold">
                    {language === "zh" ? "状态编排层" : "Orchestration"}
                  </span>
                  <span className="w-2 h-2 rounded-full bg-[#859900] animate-ping" />
                </div>
                <div className="text-xs font-bold text-[#2b3638] flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-[#2aa198]" />
                  <span>Supervisor / Orchestrator</span>
                </div>
                <div className="text-[10px] text-[#586e75] mt-1 font-mono">
                  {language === "zh" ? "有界路由 • 最大 10 步限制" : "Bounded Router • Max 10 Steps"}
                </div>
              </button>
            </div>

            {/* Connecting Arrow */}
            <div className="flex justify-center mb-6">
              <div className="h-6 w-0.5 bg-gradient-to-b from-[#2aa198] to-[#268bd2] relative">
                <span className="absolute -left-1 top-1/2 w-2.5 h-2.5 rounded-full bg-[#2aa198] blur-xs animate-packet-flow" />
              </div>
            </div>

            {/* Flow Stage 2: Planner */}
            <div className="flex justify-center mb-8">
              <button
                onClick={() => setSelectedAgent(AGENT_NODES[1])}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer w-72 text-left relative ${
                  selectedAgent.id === "planner_agent"
                    ? "bg-[#eef7f6] border-[#2aa198] ring-2 ring-[#2aa198]/20 shadow-sm"
                    : "bg-[#fcf8ed] border-[#dfd6bf] hover:border-[#cbbea2]"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[10px] font-mono text-[#2aa198] uppercase font-bold">
                    {language === "zh" ? "阶段 1: 规划" : "Stage 1"}
                  </span>
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#859900]" />
                </div>
                <div className="text-xs font-bold text-[#2b3638] flex items-center gap-2">
                  <Layers className="w-4 h-4 text-[#2aa198]" />
                  <span>Planner Agent</span>
                </div>
                <div className="text-[10px] text-[#586e75] mt-1 font-mono">
                  {language === "zh" ? "程序语义理解与攻击面分类" : "Attack Surface & Target Classification"}
                </div>
              </button>
            </div>

            {/* Connecting Bifurcation Arrows */}
            <div className="flex justify-center mb-6">
              <div className="h-6 w-0.5 bg-gradient-to-b from-[#2aa198] to-[#268bd2]" />
            </div>

            {/* Flow Stage 3: Dual Analyzers */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
              <button
                onClick={() => setSelectedAgent(AGENT_NODES[2])}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer text-left ${
                  selectedAgent.id === "source_audit_agent"
                    ? "bg-[#eef7f6] border-[#2aa198] ring-2 ring-[#2aa198]/20 shadow-sm"
                    : "bg-[#fcf8ed] border-[#dfd6bf] hover:border-[#cbbea2]"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[10px] font-mono text-[#2aa198] uppercase font-bold">
                    {language === "zh" ? "静态代码分析" : "Static Analyzer"}
                  </span>
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-[#edf5d3] text-[#859900] font-semibold">
                    {language === "zh" ? "已激活" : "Active"}
                  </span>
                </div>
                <div className="text-xs font-bold text-[#2b3638] flex items-center gap-2">
                  <FolderCode className="w-4 h-4 text-[#2aa198]" />
                  <span>Source Audit Agent</span>
                </div>
                <div className="text-[10px] text-[#586e75] mt-1 font-mono">
                  {language === "zh" ? "AST • 污点分析 • 危险 API" : "AST • Taint Analysis • Dangerous APIs"}
                </div>
              </button>

              <button
                onClick={() => setSelectedAgent(AGENT_NODES[3])}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer text-left ${
                  selectedAgent.id === "binary_analysis_agent"
                    ? "bg-[#fbf4e6] border-[#b58900] ring-2 ring-[#b58900]/20 shadow-sm"
                    : "bg-[#fcf8ed] border-[#dfd6bf] hover:border-[#cbbea2]"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[10px] font-mono text-[#b58900] uppercase font-bold">
                    {language === "zh" ? "二进制逆向分析" : "Binary Analyzer"}
                  </span>
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-[#eee8d5] text-[#586e75]">
                    ELF/PE
                  </span>
                </div>
                <div className="text-xs font-bold text-[#2b3638] flex items-center gap-2">
                  <Binary className="w-4 h-4 text-[#b58900]" />
                  <span>Binary Analysis Agent</span>
                </div>
                <div className="text-[10px] text-[#586e75] mt-1 font-mono">
                  {language === "zh" ? "反汇编 • CFG • 符号提取" : "Disassembly • CFG • Strings"}
                </div>
              </button>
            </div>

            {/* Protected-binary branch: restoration and semantic recovery */}
            <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2">
              {[AGENT_NODES[8], AGENT_NODES[9]].map((agent, index) => (
                <button
                  key={agent.id}
                  onClick={() => setSelectedAgent(agent)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer text-left ${
                    selectedAgent.id === agent.id
                      ? "bg-[#f4f1f9] border-[#6c71c4] ring-2 ring-[#6c71c4]/20 shadow-sm"
                      : "bg-[#fcf8ed] border-[#dfd6bf] hover:border-[#cbbea2]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="text-[10px] font-mono text-[#6c71c4] uppercase font-bold">
                      {index === 0 ? (language === "zh" ? "受保护映像还原" : "Image Restoration") : (language === "zh" ? "混淆语义还原" : "Semantic Recovery")}
                    </span>
                    <span className="px-1.5 rounded text-[9px] font-mono bg-[#eee8f5] text-[#6c71c4]">PE · DEX</span>
                  </div>
                  <div className="text-xs font-bold text-[#2b3638] flex items-center gap-2">
                    {index === 0 ? <ShieldCheck className="w-4 h-4 text-[#6c71c4]" /> : <Terminal className="w-4 h-4 text-[#6c71c4]" />}
                    <span>{index === 0 ? "Program Restoration Agent" : "Code Deobfuscation Agent"}</span>
                  </div>
                  <div className="text-[10px] text-[#586e75] mt-1 font-mono">
                    {index === 0 ? "识别 • OEP • IAT/PE 修复" : "CFG • 指令 • 字符串 • 语义"}
                  </div>
                </button>
              ))}
            </div>

            {/* Connecting Arrow to Fuzz */}
            <div className="flex justify-center mb-6">
              <div className="h-6 w-0.5 bg-gradient-to-b from-[#268bd2] to-[#b58900]" />
            </div>

            {/* Flow Stage 4: Dynamic Testing (Fuzz) */}
            <div className="flex justify-center mb-8">
              <button
                onClick={() => setSelectedAgent(AGENT_NODES[4])}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer w-72 text-left ${
                  selectedAgent.id === "fuzz_agent"
                    ? "bg-[#fbf4e6] border-[#b58900] ring-2 ring-[#b58900]/20 shadow-sm"
                    : "bg-[#fcf8ed] border-[#dfd6bf] hover:border-[#cbbea2]"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[10px] font-mono text-[#b58900] uppercase font-bold">
                    {language === "zh" ? "动态变异测试" : "Dynamic Engine"}
                  </span>
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-[#fce8e6] text-[#dc322f] border border-[#f5b8b5]">
                    HYBRID / FIXED BUDGET
                  </span>
                </div>
                <div className="text-xs font-bold text-[#2b3638] flex items-center gap-2">
                  <Bug className="w-4 h-4 text-[#b58900]" />
                  <span>Fuzz Agent</span>
                </div>
                <div className="text-[10px] text-[#586e75] mt-1 font-mono">
                  {language === "zh" ? "种子变异 • 崩溃捕获 • 覆盖率" : "Seed Mutation • Crash Capture • Trace"}
                </div>
              </button>
            </div>

            {/* Connecting Arrow to Verification */}
            <div className="flex justify-center mb-6">
              <div className="h-6 w-0.5 bg-gradient-to-b from-[#b58900] to-[#859900]" />
            </div>

            {/* Flow Stage 5: Independent Verification & Review */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
              <button
                onClick={() => setSelectedAgent(AGENT_NODES[5])}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer text-left relative ${
                  selectedAgent.id === "verification_agent"
                    ? "bg-[#f3f8e6] border-[#859900] ring-2 ring-[#859900]/20 shadow-sm"
                    : "bg-[#fcf8ed] border-[#dfd6bf] hover:border-[#cbbea2]"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[10px] font-mono text-[#859900] uppercase font-bold">
                    {language === "zh" ? "唯一确认写入者" : "Sole Confirmer"}
                  </span>
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#859900]" />
                </div>
                <div className="text-xs font-bold text-[#2b3638] flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-[#859900]" />
                  <span>Verification Agent</span>
                </div>
                <div className="text-[10px] text-[#586e75] mt-1 font-mono">
                  {language === "zh" ? "独立解耦复核 • 签署 CONFIRMED" : "Decoupled Verifier • Writes CONFIRMED"}
                </div>
              </button>

              <button
                onClick={() => setSelectedAgent(AGENT_NODES[6])}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer text-left ${
                  selectedAgent.id === "reviewer_agent"
                    ? "bg-[#f4f1f9] border-[#6c71c4] ring-2 ring-[#6c71c4]/20 shadow-sm"
                    : "bg-[#fcf8ed] border-[#dfd6bf] hover:border-[#cbbea2]"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[10px] font-mono text-[#6c71c4] uppercase font-bold">
                    {language === "zh" ? "二次同行仲裁" : "Peer Review"}
                  </span>
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-[#eee8d5] text-[#6c71c4]">
                    {language === "zh" ? "去误报" : "Second Look"}
                  </span>
                </div>
                <div className="text-xs font-bold text-[#2b3638] flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-[#6c71c4]" />
                  <span>Reviewer Agent</span>
                </div>
                <div className="text-[10px] text-[#586e75] mt-1 font-mono">
                  {language === "zh" ? "消解 UNCERTAIN • 结果融合" : "Resolves UNCERTAIN • Deduplication"}
                </div>
              </button>
            </div>

            {/* Connecting Arrow to Report */}
            <div className="flex justify-center mb-6">
              <div className="h-6 w-0.5 bg-gradient-to-b from-[#859900] to-[#2aa198]" />
            </div>

            {/* Flow Stage 6: Report Agent */}
            <div className="flex justify-center">
              <button
                onClick={() => setSelectedAgent(AGENT_NODES[7])}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer w-72 text-left ${
                  selectedAgent.id === "report_agent"
                    ? "bg-[#eef7f6] border-[#2aa198] ring-2 ring-[#2aa198]/20 shadow-sm"
                    : "bg-[#fcf8ed] border-[#dfd6bf] hover:border-[#cbbea2]"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[10px] font-mono text-[#2aa198] uppercase font-bold">
                    {language === "zh" ? "最终情报汇聚" : "Final Synthesis"}
                  </span>
                  <FileText className="w-3.5 h-3.5 text-[#2aa198]" />
                </div>
                <div className="text-xs font-bold text-[#2b3638] flex items-center gap-2">
                  <FileText className="w-4 h-4 text-[#2aa198]" />
                  <span>Report Agent</span>
                </div>
                <div className="text-[10px] text-[#586e75] mt-1 font-mono">
                  {language === "zh" ? "审计报告生成 • 修复路线图" : "Audit Intelligence • Remediation Plan"}
                </div>
              </button>
            </div>
          </div>
        </div>

        {/* Right: Agent Inspector Panel */}
        <div className="lg:col-span-4 space-y-4">
          <div className="p-5 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-[#dfd6bf] pb-3">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#2aa198] animate-pulse" />
                <span className="text-xs font-bold text-[#2b3638] font-mono">
                  {language === "zh" ? "智能体规格契约" : "AGENT SPECIFICATION"}
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#eee8d5] text-[#2aa198] font-bold">
                {selectedAgent.category.toUpperCase()}
              </span>
            </div>

            <div>
              <h3 className="text-base font-bold text-[#2b3638]">{selectedAgent.name}</h3>
              <p className="text-xs font-mono text-[#2aa198] font-semibold mt-0.5">{selectedAgent.role}</p>
              <div className="mt-2 text-xs text-[#586e75] leading-relaxed">
                {selectedAgent.description}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-[#f5eed9] border border-[#e2d9c4] text-xs font-mono">
              <span className="text-[10px] text-[#586e75] uppercase block mb-1">
                {language === "zh" ? "源代码模块路径" : "Source Module Path"}
              </span>
              <span className="text-[#2b3638] select-all font-medium">{selectedAgent.module}</span>
            </div>

            {/* Input Contract */}
            <div>
              <span className="text-[11px] font-semibold text-[#586e75] uppercase tracking-wider block mb-1.5">
                {language === "zh" ? "输入契约 (公开 Schema)" : "Input Contract (Public Schema)"}
              </span>
              <div className="flex flex-wrap gap-1.5">
                {selectedAgent.inputContract.map((input) => (
                  <span
                    key={input}
                    className="px-2 py-1 rounded bg-[#eee8d5] border border-[#dfd6bf] text-[11px] font-mono text-[#2b3638]"
                  >
                    {input}
                  </span>
                ))}
              </div>
            </div>

            {/* Output Contract */}
            <div>
              <span className="text-[11px] font-semibold text-[#586e75] uppercase tracking-wider block mb-1.5">
                {language === "zh" ? "输出契约 (冻结协议)" : "Output Contract (Frozen Protocol)"}
              </span>
              <div className="flex flex-wrap gap-1.5">
                {selectedAgent.outputContract.map((output) => (
                  <span
                    key={output}
                    className="px-2 py-1 rounded bg-[#eef7f6] border border-[#bfe3e0] text-[11px] font-mono text-[#2aa198] font-medium"
                  >
                    {output}
                  </span>
                ))}
              </div>
            </div>

            {/* Produced Evidence Types */}
            {selectedAgent.evidenceTypesProduced.length > 0 && (
              <div>
                <span className="text-[11px] font-semibold text-[#586e75] uppercase tracking-wider block mb-1.5">
                  {language === "zh" ? "生成的证据实体类型" : "Produced Evidence Types"}
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {selectedAgent.evidenceTypesProduced.map((ev) => (
                    <span
                      key={ev}
                      className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#edf5d3] text-[#859900] border border-[#cce38d] font-semibold"
                    >
                      {ev}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* AGENTS.md Architectural Safeguards */}
            <div className="p-3.5 rounded-xl bg-[#f5eed9] border border-[#e2d9c4] text-xs space-y-2">
              <span className="text-[11px] font-bold text-[#b58900] flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5" />
                {language === "zh" ? "AGENTS.md 规范与治理规则" : "AGENTS.md Governance Rule"}
              </span>
              <p className="text-[11px] text-[#586e75] leading-relaxed">
                {language === "zh" ? (
                  selectedAgent.id === "verification_agent"
                    ? "原则 7 & 9：发现模块不能直接将状态设置为 CONFIRMED。只有 Verification 复核层是 CONFIRMED 与 REJECTED 状态的唯一合法写入者。"
                    : selectedAgent.id === "source_audit_agent"
                    ? "原则 8 (Evidence First)：大语言模型的自然语言结论不是充分证据，必须严格关联 AST 源码位置或跨过程污点流动路径。"
                    : selectedAgent.id === "fuzz_agent"
                    ? "原则 10 (Fuzz 安全原则)：当前仅允许在沙箱中测试授权 Benchmark 程序，严禁在宿主系统直接运行未知潜在恶意二进制。"
                    : "原则 5 & 21：跨 Agent 调度只能经过 Supervisor 编排层，禁止 Agent 之间直接调用具体实现；必须通过结构化 AgentMessage 传递。"
                ) : (
                  selectedAgent.id === "verification_agent"
                    ? "Rule 7 & 9: Discovery modules cannot set CONFIRMED. The Verification layer is the sole authorizer of verified vulnerabilities."
                    : selectedAgent.id === "source_audit_agent"
                    ? "Rule 8 (Evidence First): LLM natural language is not sufficient proof. Code locations and taint paths must be formally linked as Evidence."
                    : selectedAgent.id === "fuzz_agent"
                    ? "Rule 10 (Fuzz Safety): Only authorized benchmark programs in sandboxed containers are tested. Direct host execution is forbidden."
                    : "Rule 5: Agents communicate strictly via structured AgentMessage. Cross-agent orchestration passes exclusively through the Supervisor."
                )}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
