import React, { useState, useEffect, useCallback } from "react";
import { Navbar } from "./components/Navbar.js";
import { CommandPalette } from "./components/CommandPalette.js";
import { DashboardView } from "./components/DashboardView.js";
import { AgentTopologyView } from "./components/AgentTopologyView.js";
import { EvidenceChainView } from "./components/EvidenceChainView.js";
import { VulnerabilitiesView } from "./components/VulnerabilitiesView.js";
import { ReportView } from "./components/ReportView.js";
import { EventTraceView } from "./components/EventTraceView.js";
import { ApiConsoleView } from "./components/ApiConsoleView.js";
import { useTranslation } from "./i18n.js";
import {
  Task,
  DomainEvent,
  VulnerabilityCandidate,
  Evidence,
  ReportResult,
  ActiveTab,
} from "./types.js";

export default function App() {
  const { t, language } = useTranslation();
  const [tasks, setTasks] = useState<Task[]>([]);
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>("dashboard");
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | undefined>(undefined);

  const [events, setEvents] = useState<DomainEvent[]>([]);
  const [findings, setFindings] = useState<VulnerabilityCandidate[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [report, setReport] = useState<ReportResult | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);

  // Fetch Tasks
  const fetchTasks = useCallback(async () => {
    try {
      const res = await fetch("/api/tasks");
      if (res.ok) {
        const data: Task[] = await res.json();
        setTasks(data);
        if (data.length > 0 && !activeTaskId) {
          setActiveTaskId(data[0].task_id);
        }
      }
    } catch (err) {
      console.error("Failed to load tasks:", err);
    }
  }, [activeTaskId]);

  // Fetch Active Task Data
  const fetchActiveTaskData = useCallback(async (taskId: string) => {
    try {
      const [eventsRes, findingsRes, evidenceRes, reportRes] = await Promise.all([
        fetch(`/api/tasks/${taskId}/events`),
        fetch(`/api/tasks/${taskId}/findings`),
        fetch(`/api/tasks/${taskId}/evidence`),
        fetch(`/api/tasks/${taskId}/report`),
      ]);

      if (eventsRes.ok) setEvents(await eventsRes.json());
      if (findingsRes.ok) setFindings(await findingsRes.json());
      if (evidenceRes.ok) setEvidence(await evidenceRes.json());
      if (reportRes.ok) setReport(await reportRes.json());
      else setReport(null);
    } catch (err) {
      console.error("Failed to fetch task details:", err);
    }
  }, []);

  useEffect(() => {
    const init = async () => {
      setIsLoading(true);
      await fetchTasks();
      setIsLoading(false);
    };
    init();
  }, [fetchTasks]);

  useEffect(() => {
    if (activeTaskId) {
      fetchActiveTaskData(activeTaskId);
    }
  }, [activeTaskId, fetchActiveTaskData]);

  // Keyboard shortcut for Cmd+K / Ctrl+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setIsCommandPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await fetchTasks();
    if (activeTaskId) {
      await fetchActiveTaskData(activeTaskId);
    }
    setIsRefreshing(false);
  };

  const handleTriggerRun = async () => {
    if (!activeTaskId || isRunning) return;
    setIsRunning(true);
    try {
      const res = await fetch(`/api/tasks/${activeTaskId}/run`, {
        method: "POST",
      });
      if (res.ok) {
        await fetchTasks();
        await fetchActiveTaskData(activeTaskId);
      }
    } catch (err) {
      console.error("Pipeline run failed:", err);
    } finally {
      setIsRunning(false);
    }
  };

  const handleLaunchNewTask = async (
    targetPath: string,
    targetType: "source" | "binary",
    language?: string
  ) => {
    try {
      const res = await fetch("/api/tasks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_path: targetPath,
          target_type: targetType,
          language: language || (targetType === "binary" ? "ELF" : "C"),
        }),
      });
      if (res.ok) {
        const newTask: Task = await res.json();
        await fetchTasks();
        setActiveTaskId(newTask.task_id);
        // Automatically run pipeline on the new task
        setIsRunning(true);
        await fetch(`/api/tasks/${newTask.task_id}/run`, { method: "POST" });
        await fetchTasks();
        await fetchActiveTaskData(newTask.task_id);
        setIsRunning(false);
      }
    } catch (err) {
      console.error("Failed to launch task:", err);
      setIsRunning(false);
    }
  };

  const activeTask = tasks.find((t) => t.task_id === activeTaskId) || tasks[0];

  const handleInspectEvidence = (evidenceId: string) => {
    setSelectedEvidenceId(evidenceId);
    setActiveTab("evidence");
  };

  return (
    <div className="min-h-screen bg-[#fdf6e3] text-[#2b3638] flex flex-col font-sans selection:bg-[#e4dcbe] selection:text-[#2b3638]">
      {/* Top Navbar with Tab Navigation and Controls */}
      <Navbar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
        tasks={tasks}
        activeTask={activeTask}
        onSelectTask={(id) => {
          setActiveTaskId(id);
          fetchActiveTaskData(id);
        }}
        onTriggerRun={handleTriggerRun}
        onRefresh={handleRefresh}
        isRunning={isRunning}
      />

      {/* Main Workspace View Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {isLoading ? (
          <div className="p-24 text-center space-y-3 font-mono">
            <div className="w-8 h-8 rounded-full border-2 border-[#2aa198] border-t-transparent animate-spin mx-auto" />
            <p className="text-xs text-[#586e75]">
              {language === "zh" ? "正在加载 VulnAgent 多智能体分析环境..." : "Loading VulnAgent Autonomous Environment..."}
            </p>
          </div>
        ) : !activeTask ? (
          <div className="p-16 rounded-2xl bg-[#fcf8ed] border border-[#dfd6bf] text-center space-y-4 shadow-sm">
            <h3 className="text-base font-bold text-[#2b3638]">
              {language === "zh" ? "未发现进行中的安全审计任务" : "No Active Audit Tasks Found"}
            </h3>
            <p className="text-xs text-[#586e75] max-w-md mx-auto">
              {language === "zh"
                ? "请初始化或选择一个程序样本，启动源码静态 AST 污点审计、动态模糊测试与独立复核。"
                : "Initialize a new target to begin multi-agent AST static analysis, dynamic fuzzing, and verification."}
            </p>
            <button
              onClick={() =>
                handleLaunchNewTask("samples/c_buffer_overflow/vuln_server.c", "source", "c")
              }
              className="px-4 py-2 rounded-xl bg-[#2aa198] hover:bg-[#238b83] text-white font-bold text-xs shadow-sm transition-colors cursor-pointer"
            >
              {language === "zh" ? "加载演示审计任务 (C 栈溢出)" : "Seed Demo Audit Task"}
            </button>
          </div>
        ) : (
          <>
            {activeTab === "dashboard" && (
              <DashboardView
                task={activeTask}
                findings={findings}
                evidenceList={evidence}
                events={events}
                onTriggerRun={handleTriggerRun}
                isRunning={isRunning}
                onNavigateTab={setActiveTab}
                onSelectEvidence={handleInspectEvidence}
                onLaunchNewTask={handleLaunchNewTask}
              />
            )}

            {activeTab === "topology" && (
              <AgentTopologyView
                task={activeTask}
                events={events}
                onTriggerRun={handleTriggerRun}
                isRunning={isRunning}
              />
            )}

            {activeTab === "evidence" && (
              <EvidenceChainView
                evidenceList={evidence}
                initialSelectedId={selectedEvidenceId}
              />
            )}

            {activeTab === "vulnerabilities" && (
              <VulnerabilitiesView
                findings={findings}
                evidenceList={evidence}
                onInspectEvidence={handleInspectEvidence}
              />
            )}

            {activeTab === "report" && (
              <ReportView report={report} task={activeTask} />
            )}

            {activeTab === "trace" && (
              <EventTraceView
                events={events}
                taskId={activeTask.task_id}
                onTriggerRun={handleTriggerRun}
                isRunning={isRunning}
              />
            )}

            {activeTab === "api" && (
              <ApiConsoleView taskId={activeTask.task_id} />
            )}
          </>
        )}
      </main>

      {/* Global Command Palette (⌘K) */}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onSelectTab={setActiveTab}
        onSelectTask={(id) => {
          setActiveTaskId(id);
          fetchActiveTaskData(id);
        }}
        onTriggerRun={handleTriggerRun}
        tasks={tasks}
        activeTask={activeTask}
      />

      {/* Antigravity / Solarized Status Bar Footer */}
      <footer className="border-t border-[#dfd6bf] bg-[#eee8d5] text-[#586e75] text-xs py-2.5 mt-auto font-mono select-none">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-2 text-[11px]">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#859900]" />
            <span className="text-[#2b3638] font-semibold">feature/platform</span>
            <span>&bull;</span>
            <span className="text-[#586e75]">VulnAgent OS v0.2.0</span>
            <span>&bull;</span>
            <span className="text-[#859900]">🌿 工作区干净</span>
          </div>

          <div className="flex items-center gap-3 text-[#657b83]">
            <span>Evidence First</span>
            <span>&bull;</span>
            <span>Decoupled Verification</span>
            <span>&bull;</span>
            <span className="px-1.5 py-0.5 rounded bg-[#e4dcbe] text-[#586e75] font-semibold">
              Bounded DAG Execution
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
