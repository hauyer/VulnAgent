import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";

export type Language = "zh" | "en";

interface TranslationDictionary {
  [key: string]: string;
}

const zhTranslations: TranslationDictionary = {
  // Brand & App
  appTitle: "VulnAgent",
  appSubtitle: "自研多智能体软件漏洞分析与挖掘平台",
  courseBadge: "网络空间安全课程设计",
  versionBadge: "V0.4 多智能体证据链增强版",
  systemStatus: "系统状态",
  statusOnline: "API 在线 (端口 8000)",

  // Navigation
  navDashboard: "态势大屏",
  navTopology: "Agent编排拓扑",
  navEvidence: "证据链矩阵",
  navVulnerabilities: "漏洞候选卷宗",
  navReport: "审计报告",
  navTrace: "事件遥测",
  navApi: "API控制台",

  // Navbar actions
  currentTarget: "当前审计目标",
  switchTarget: "切换目标",
  executePipeline: "启动自主挖掘流水线",
  executingPipeline: "多智能体推理中...",
  commandPalette: "快捷指令",
  refresh: "刷新数据",
  languageToggle: "语言切换",

  // Statuses
  status_completed: "已完成",
  status_analyzing: "静态/逆向分析中",
  status_planning: "智能规划中",
  status_verifying: "独立复核中",
  status_dynamic_testing: "模糊测试中",
  status_profiling: "目标探查中",
  status_created: "已就绪",
  status_failed: "失败",

  // Vulnerability Statuses
  vuln_candidate: "候选 (Candidate)",
  vuln_verifying: "复核中 (Verifying)",
  vuln_confirmed: "已确认漏洞 (Confirmed)",
  vuln_rejected: "误报剔除 (Rejected)",
  vuln_uncertain: "存疑待查 (Uncertain)",

  // Severities
  sev_CRITICAL: "严重 (Critical)",
  sev_HIGH: "高危 (High)",
  sev_MEDIUM: "中危 (Medium)",
  sev_LOW: "低危 (Low)",
  sev_INFO: "提示 (Info)",

  // Dashboard View
  dashHeroTitle: "VulnAgent 自主多智能体软件漏洞分析平台",
  dashHeroSubtitle: "网络空间安全课程设计 · 综合静态代码审计、二进制逆向、模糊测试、独立漏洞复核与证据链存证的多智能体协同挖掘体系",
  dashStatsConfirmed: "独立复核确认项",
  dashStatsConfirmedSub: "由 Verification 层依据当前证据作出确认",
  dashStatsEvidence: "证据链存证数",
  dashStatsEvidenceSub: "源码位置、静态分析、运行轨迹与复核证据",
  dashStatsAgents: "多智能体协同运行",
  dashStatsAgentsSub: "LangGraph 状态图与有界路由机制",
  dashStatsStatus: "当前任务分析状态",
  dashStatsStatusSub: "端到端自动化安全审计流水线",
  dashProtocolPill: "遵循冻结接口规范 · 证据在先(Evidence-First) · 独立复核解耦",

  dashInnovationsTitle: "课程设计核心自研创新机制",
  dashInnovationsSubtitle: "严格遵守 AGENTS.md 自研优先原则，拒绝简单大模型 API 封装与传统扫描器换壳",
  inno1Title: "多智能体状态图编排 (Agent Runtime)",
  inno1Desc: "基于 LangGraph 状态机与 Supervisor 结构化路由，RuntimeState 严格维护编排状态，具备最大步数限制与确定性回退机制。",
  inno2Title: "证据在先原则 (Evidence-First)",
  inno2Desc: "严禁仅凭大模型自然语言判定漏洞。所有候选必须关联源码位置、结构化分析结果、受控运行轨迹或反汇编等统一证据实体。",
  inno3Title: "独立漏洞复核机制 (Independent Verification)",
  inno3Desc: "发现模块（Source/Binary/Fuzz）与验证模块严格解耦，发现模块禁止输出 CONFIRMED，仅 Verification 层享有确认权。",
  inno4Title: "静态分析与 Fuzz 动态联动机制",
  inno4Desc: "静态危险点生成确定性风险提示，在固定预算内引导受控 Fuzz；运行轨迹与崩溃指纹再回流到独立复核。",

  dashBenchmarkTitle: "系统漏洞评测实验基准套件 (Benchmark Suites)",
  dashBenchmarkSubtitle: "切换仓库内自研源码与二进制教学样本，使用统一清单和固定指标评估检测、复核及证据完整性",
  dashAgentFleetTitle: "6 大专业安全智能体协同矩阵",
  dashAgentFleetSubtitle: "继承统一 BaseAgent，通过标准 AgentMessage 结构化消息通信，职责清晰，无缝协同",

  // Topology View
  topoTitle: "多智能体编排 DAG 拓扑与运行时状态机",
  topoSubtitle: "基于 LangGraph 状态图模型 · Supervisor 结构化路由 · 跨智能体解耦与有限循环守护",
  topoLegendReady: "就绪状态",
  topoLegendRunning: "推理/执行中",
  topoLegendCompleted: "已完成分析",
  topoInspectorTitle: "智能体检查器与通信协议契约",
  topoInspectorSubtitle: "点击拓扑节点查看该智能体的职责定位、输入/输出契约与执行状态",
  topoAgentDuty: "职责说明",
  topoInputContract: "输入契约",
  topoOutputContract: "输出契约",
  topoLifecycle: "生命周期钩子",
  topoStateBound: "有界循环限制",

  // Evidence View
  eviTitle: "多维度漏洞证据链矩阵与存证库",
  eviSubtitle: "证据在先原则 (Evidence-First) · 拒绝无依据的模型结论 · 源码、二进制、运行轨迹与复核记录全链路可查",
  eviFilterAll: "全部证据",
  eviFilterSource: "源码位置 (Source)",
  eviFilterCrash: "崩溃转储 (Crash Log)",
  eviFilterVerif: "复核结论 (Verification)",
  eviFilterCall: "调用路径 (Call Path)",
  eviFilterTaint: "污点路径 (Taint Path)",
  eviReliability: "可信度评分",
  eviSourceAgent: "采集智能体",
  eviArtifactPath: "存证物路径",
  eviSnippetTitle: "源码 / 崩溃 / 汇编上下文查看器",
  eviRawJson: "结构化证据数据 (Evidence Payload)",
  eviNoData: "暂未选择证据或无对应存证物",

  // Vulnerabilities View
  vulnTitle: "统一漏洞候选卷宗与复核看板",
  vulnSubtitle: "遵循公共冻结 VulnerabilityCandidate Schema · 独立复核机制消除误报 · 证据闭环追踪",
  vulnFilterAll: "全部卷宗",
  vulnFilterCandidate: "待验证候选",
  vulnFilterVerifying: "复核验证中",
  vulnFilterConfirmed: "独立复核确认",
  vulnFilterRejected: "已剔除误报",
  vulnFilterUncertain: "存疑待查",
  vulnTargetTitle: "受影响目标",
  vulnDiscoveredBy: "发现智能体",
  vulnConfidence: "置信度评分",
  vulnSeverity: "风险严重度",
  vulnEvidenceRef: "关联证据实体",
  vulnVerificationDossier: "独立复核流程与判定依据",
  vulnVerificationNote: "根据 AGENTS.md 规范，发现智能体不得直接标记 CONFIRMED；VerificationAgent 必须独立评估关联证据并记录结构化复核结果。",
  vulnRemediationTitle: "安全加固与修复建议",

  // Report View
  repTitle: "软件安全审计与漏洞挖掘总报告",
  repSubtitle: "由当前任务数据自动生成 · 汇总结构化发现、独立复核、证据链与修复建议",
  repExportMd: "导出 Markdown",
  repExportJson: "导出 JSON",
  repPrint: "打印安全报告",
  repExecutiveSummary: "执行摘要 (Executive Summary)",
  repTargetInfo: "审计目标元数据",
  repMetricsTitle: "漏洞风险雷达指标",
  repConfirmedFindings: "已确认成立的漏洞明细清单",
  repRemediationTitle: "工程级修复路线图与安全建议",
  repGeneratedBy: "报告编制智能体",

  // Event Trace View
  traceTitle: "领域事件流与运行时遥测控制台",
  traceSubtitle: "基于 AgentMessage 与 DomainEvent 协议 · 毫秒级时间戳 · 全流程可解释审计轨迹",
  traceAutoScroll: "自动滚动",
  traceFilterType: "过滤事件类型",
  traceAllEvents: "全部事件类型",
  traceSearchPlaceholder: "过滤事件类型、载荷文本、智能体标识...",
  traceInspectPayload: "点击展开/折叠结构化载荷数据",
  traceTotalEvents: "事件存证总数",

  // API Console View
  apiTitle: "REST API 与自动化开发者控制台",
  apiSubtitle: "交互式测试平台 · 支持触发自主编排流水线、查询证据链矩阵与调取审计报告 (OpenAPI 3.1 • API 端口 8000)",
  apiEndpointsList: "平台可用端点清单",
  apiSendRequest: "发送测试请求",
  apiSending: "请求发送中...",
  apiCurlTitle: "生成的 cURL 命令行语句",
  apiLiveResponse: "服务器实时响应结果",
  apiCopyCurl: "复制 cURL",
  apiCopied: "已复制 cURL",
  apiWaitingResponse: "正在等待后端服务响应...",
  apiPromptTest: "点击「发送测试请求」可直接向当前容器发起 API 探测",

  // Command Palette
  cmdPlaceholder: "键入命令、搜索审计目标或切换工作区视图... (Esc 退出)",
  cmdQuickActions: "快速操作",
  cmdRerunTitle: "重新执行自主挖掘流水线",
  cmdRerunDesc: "对当前目标重新调度 Planner、Source/Binary 审计、Fuzz 与复核智能体",
  cmdWorkspaceViews: "工作区视图跳转",
  cmdAuditTasks: "安全审计任务列表",
  cmdNavigationTip: "键盘导航: ↑↓ 回车选择 · Esc 退出",
  cmdJump: "跳转 →",

  // Footer
  footerCopyright: "VulnAgent · 网络空间安全课程设计自研项目",
  footerArchText: "基于 LangGraph 状态图与证据在先原则的多智能体漏洞分析平台",
  footerContractText: "冻结契约: Task · AgentMessage · VulnerabilityCandidate · Evidence",
};

const enTranslations: TranslationDictionary = {
  // Brand & App
  appTitle: "VulnAgent",
  appSubtitle: "Multi-Agent Vulnerability Mining & Analysis Platform",
  courseBadge: "Cybersecurity Course Design",
  versionBadge: "V0.4 Evidence-First Multi-Agent",
  systemStatus: "System Status",
  statusOnline: "API Online (Port 8000)",

  // Navigation
  navDashboard: "Mission Control",
  navTopology: "Agent Topology",
  navEvidence: "Evidence Chain",
  navVulnerabilities: "Vulnerabilities",
  navReport: "Audit Report",
  navTrace: "Event Telemetry",
  navApi: "API Console",

  // Navbar actions
  currentTarget: "Current Target",
  switchTarget: "Switch Target",
  executePipeline: "Execute Autonomous Pipeline",
  executingPipeline: "Multi-Agent Reasoning...",
  commandPalette: "Command Palette",
  refresh: "Refresh Data",
  languageToggle: "Language Switch",

  // Statuses
  status_completed: "Completed",
  status_analyzing: "Analyzing",
  status_planning: "Planning",
  status_verifying: "Verifying",
  status_dynamic_testing: "Dynamic Fuzzing",
  status_profiling: "Profiling",
  status_created: "Ready",
  status_failed: "Failed",

  // Vulnerability Statuses
  vuln_candidate: "Candidate",
  vuln_verifying: "Verifying",
  vuln_confirmed: "Confirmed Vulnerability",
  vuln_rejected: "Rejected (False Positive)",
  vuln_uncertain: "Uncertain",

  // Severities
  sev_CRITICAL: "Critical",
  sev_HIGH: "High",
  sev_MEDIUM: "Medium",
  sev_LOW: "Low",
  sev_INFO: "Info",

  // Dashboard View
  dashHeroTitle: "VulnAgent Autonomous Multi-Agent Vulnerability Mining Platform",
  dashHeroSubtitle: "Cybersecurity Course Design Project · Comprehensive software vulnerability discovery system combining static audit, binary analysis, fuzzing, independent verification, and evidence chains",
  dashStatsConfirmed: "Confirmed Vulnerabilities",
  dashStatsConfirmedSub: "Confirmed by the Verification layer from current evidence",
  dashStatsEvidence: "Evidence Chain Artifacts",
  dashStatsEvidenceSub: "Source locations, static results, runtime traces, and verification evidence",
  dashStatsAgents: "Active Multi-Agent Nodes",
  dashStatsAgentsSub: "LangGraph state machine with bounded routing",
  dashStatsStatus: "Current Task Status",
  dashStatsStatusSub: "End-to-end automated security audit pipeline",
  dashProtocolPill: "Public Contract Frozen · Evidence-First Principle · Independent Verification",

  dashInnovationsTitle: "Core Self-Developed Architectural Innovations",
  dashInnovationsSubtitle: "Strictly adhering to AGENTS.md self-developed principles, avoiding shallow LLM API wrappers or repackaged scanners",
  inno1Title: "Multi-Agent State Graph (Agent Runtime)",
  inno1Desc: "Based on LangGraph state machines and Supervisor structured routing. RuntimeState strictly manages orchestration with bounded loops and fallback.",
  inno2Title: "Evidence-First Principle",
  inno2Desc: "Strictly forbids declaring vulnerabilities purely via LLM natural language. All findings must bind to source locations, AST taint, crash dumps, or disassemblies.",
  inno3Title: "Independent Verification & De-duplication",
  inno3Desc: "Discovery modules (Source/Binary/Fuzz) are decoupled from verification. Discovery agents cannot set CONFIRMED status; only Verification layer can confirm.",
  inno4Title: "Static Analysis & Dynamic Fuzzing Synergy",
  inno4Desc: "Static risk locations produce deterministic guidance for a fixed-budget controlled fuzzer; runtime traces and crash fingerprints feed independent verification.",

  dashBenchmarkTitle: "Vulnerability Benchmark Evaluation Suites",
  dashBenchmarkSubtitle: "Run repository-owned source and binary teaching samples with shared manifests and reproducible detection, verification, and evidence metrics",
  dashAgentFleetTitle: "Collaborative Agent Fleet (6 Specialized Roles)",
  dashAgentFleetSubtitle: "Inheriting from unified BaseAgent, communicating through structured AgentMessage protocols with clear boundaries",

  // Topology View
  topoTitle: "Multi-Agent DAG Topology & Runtime State Graph",
  topoSubtitle: "LangGraph state machine model · Supervisor structured routing · Decoupled agents with bounded execution guardrails",
  topoLegendReady: "Ready State",
  topoLegendRunning: "Reasoning / Running",
  topoLegendCompleted: "Analysis Completed",
  topoInspectorTitle: "Agent Inspector & Protocol Contract",
  topoInspectorSubtitle: "Click any topology node to inspect duties, I/O schemas, and execution states",
  topoAgentDuty: "Core Duty",
  topoInputContract: "Input Contract",
  topoOutputContract: "Output Contract",
  topoLifecycle: "Lifecycle Hooks",
  topoStateBound: "Bounded Step Limits",

  // Evidence View
  eviTitle: "Multi-Dimensional Evidence Chain Matrix",
  eviSubtitle: "Evidence-First · No ungrounded model conclusions · Traceable source, binary, runtime, and verification records",
  eviFilterAll: "All Evidence",
  eviFilterSource: "Source Location",
  eviFilterCrash: "Crash Log",
  eviFilterVerif: "Verification Result",
  eviFilterCall: "Call Path",
  eviFilterTaint: "Taint Path",
  eviReliability: "Reliability Score",
  eviSourceAgent: "Generating Agent",
  eviArtifactPath: "Artifact Path",
  eviSnippetTitle: "Source / Crash / Disassembly Inspector",
  eviRawJson: "Structured Evidence Payload (JSON)",
  eviNoData: "No evidence selected or artifact unavailable",

  // Vulnerabilities View
  vulnTitle: "Unified Vulnerability Dossier & Verification Board",
  vulnSubtitle: "Adhering to public VulnerabilityCandidate Schema · Independent verification eliminates false positives · Evidence traceability",
  vulnFilterAll: "All Candidates",
  vulnFilterCandidate: "Pending Candidates",
  vulnFilterVerifying: "Verifying in Progress",
  vulnFilterConfirmed: "Confirmed Vulnerabilities",
  vulnFilterRejected: "Rejected (False Positives)",
  vulnFilterUncertain: "Uncertain Findings",
  vulnTargetTitle: "Affected Target",
  vulnDiscoveredBy: "Discovery Agent",
  vulnConfidence: "Confidence Score",
  vulnSeverity: "Risk Severity",
  vulnEvidenceRef: "Associated Evidence",
  vulnVerificationDossier: "Independent Verification & Rationale",
  vulnVerificationNote: "Per AGENTS.md, discovery agents cannot mark CONFIRMED directly. VerificationAgent must independently evaluate linked evidence and record a structured verdict.",
  vulnRemediationTitle: "Hardening & Remediation Guidance",

  // Report View
  repTitle: "Software Security Audit & Vulnerability Report",
  repSubtitle: "Generated from current task data · Structured findings, verification, evidence, and remediation guidance",
  repExportMd: "Export Markdown",
  repExportJson: "Export JSON",
  repPrint: "Print Security Report",
  repExecutiveSummary: "Executive Summary",
  repTargetInfo: "Target Metadata",
  repMetricsTitle: "Vulnerability Risk Metrics",
  repConfirmedFindings: "Confirmed Vulnerabilities Breakdown",
  repRemediationTitle: "Remediation Roadmap & Hardening Guidelines",
  repGeneratedBy: "Report Author Agent",

  // Event Trace View
  traceTitle: "Domain Event Stream & Runtime Telemetry",
  traceSubtitle: "Compliant with AgentMessage & DomainEvent protocol · Millisecond timestamps · Fully explainable audit trail",
  traceAutoScroll: "Auto Scroll",
  traceFilterType: "Filter Event Type",
  traceAllEvents: "All Event Types",
  traceSearchPlaceholder: "Filter event types, payload text, agent IDs...",
  traceInspectPayload: "Click to toggle structured payload data",
  traceTotalEvents: "Total Event Records",

  // API Console View
  apiTitle: "REST API & Autonomous Developer Console",
  apiSubtitle: "Interactive playground for triggering orchestration runs, querying evidence chains, and fetching reports (OpenAPI 3.1 • API Port 8000)",
  apiEndpointsList: "Available Platform Endpoints",
  apiSendRequest: "Send Request",
  apiSending: "Sending...",
  apiCurlTitle: "Generated cURL CLI Command",
  apiLiveResponse: "Live Server Response",
  apiCopyCurl: "Copy cURL",
  apiCopied: "Copied cURL",
  apiWaitingResponse: "Waiting for server response...",
  apiPromptTest: "Click 'Send Request' to test this API route through the UI proxy to API port 8000.",

  // Command Palette
  cmdPlaceholder: "Type a command, search targets, or switch views... (Esc to exit)",
  cmdQuickActions: "Quick Actions",
  cmdRerunTitle: "Re-Execute Autonomous Pipeline",
  cmdRerunDesc: "Trigger Planner, Source/Binary Audit, Fuzz, and Verification on current target",
  cmdWorkspaceViews: "Workspace Views",
  cmdAuditTasks: "Audit Tasks",
  cmdNavigationTip: "Navigation: ↑↓ Enter · Esc to dismiss",
  cmdJump: "Jump →",

  // Footer
  footerCopyright: "VulnAgent · Cybersecurity Course Design Autonomous Platform",
  footerArchText: "Multi-Agent Vulnerability Analysis Platform based on LangGraph & Evidence-First Principle",
  footerContractText: "Public Contracts: Task · AgentMessage · VulnerabilityCandidate · Evidence",
};

interface LanguageContextType {
  language: Language;
  setLanguage: (lang: Language) => void;
  toggleLanguage: () => void;
  t: (key: string) => string;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

export const LanguageProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  // Default to Chinese ('zh') as requested by user
  const [language, setLanguageState] = useState<Language>(() => {
    const saved = localStorage.getItem("vulnagent_lang");
    return (saved === "en" || saved === "zh") ? saved : "zh";
  });

  const setLanguage = (lang: Language) => {
    setLanguageState(lang);
    localStorage.setItem("vulnagent_lang", lang);
  };

  const toggleLanguage = () => {
    setLanguage(language === "zh" ? "en" : "zh");
  };

  const t = (key: string): string => {
    const dict = language === "zh" ? zhTranslations : enTranslations;
    return dict[key] || enTranslations[key] || key;
  };

  return (
    <LanguageContext.Provider value={{ language, setLanguage, toggleLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  );
};

export const useTranslation = (): LanguageContextType => {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error("useTranslation must be used within a LanguageProvider");
  }
  return context;
};
