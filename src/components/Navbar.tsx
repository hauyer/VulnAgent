import React from "react";
import {
  Shield,
  Activity,
  Layers,
  FileText,
  Terminal,
  Database,
  Search,
  Zap,
  Play,
  RotateCcw,
  Sparkles,
  ChevronDown,
  Languages,
} from "lucide-react";
import { ActiveTab, Task } from "../types.js";
import { useTranslation } from "../i18n.js";

interface NavbarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  onOpenCommandPalette: () => void;
  tasks: Task[];
  activeTask?: Task;
  onSelectTask: (taskId: string) => void;
  onTriggerRun: () => void;
  onRefresh: () => void;
  isRunning: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onSelectTab,
  onOpenCommandPalette,
  tasks,
  activeTask,
  onSelectTask,
  onTriggerRun,
  onRefresh,
  isRunning,
}) => {
  const { t, language, toggleLanguage } = useTranslation();
  const canRun = activeTask?.status === "created";

  const NAV_ITEMS: { id: ActiveTab; label: string; icon: any; badge?: string }[] = [
    { id: "dashboard", label: t("navDashboard"), icon: Sparkles },
    { id: "topology", label: t("navTopology"), icon: Layers, badge: "DAG" },
    { id: "evidence", label: t("navEvidence"), icon: Database },
    { id: "vulnerabilities", label: t("navVulnerabilities"), icon: Shield },
    { id: "report", label: t("navReport"), icon: FileText },
    { id: "trace", label: t("navTrace"), icon: Activity },
    { id: "api", label: t("navApi"), icon: Terminal },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-[#dfd6bf] bg-[#eee8d5]/95 backdrop-blur-md">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 flex items-center justify-between h-16 gap-4">
        {/* Left: Brand & Target Switcher */}
        <div className="flex items-center gap-4 min-w-0">
          <div
            onClick={() => onSelectTab("dashboard")}
            className="flex items-center gap-2.5 cursor-pointer group select-none"
          >
            <div className="relative w-9 h-9 rounded-xl bg-gradient-to-br from-[#2aa198] to-[#268bd2] flex items-center justify-center text-white shadow-[0_2px_10px_rgba(42,161,152,0.25)]">
              <Shield className="w-5 h-5 fill-current" />
              <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-[#859900] border-2 border-[#eee8d5]" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-extrabold text-sm tracking-tight text-[#2b3638] font-sans">
                  VulnAgent
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#e6deca] text-[#2aa198] border border-[#d2c8af] font-bold">
                  v0.4
                </span>
              </div>
              <span className="text-[10px] font-sans text-[#586e75] block -mt-0.5 font-medium">
                {language === "zh" ? "多智能体漏洞挖掘平台" : "Multi-Agent OS"}
              </span>
            </div>
          </div>

          {/* Active Target Selector Badge */}
          {tasks.length > 0 && activeTask && (
            <div className="hidden md:flex items-center gap-1.5 pl-3 border-l border-[#dfd6bf]">
              <span className="text-[11px] font-sans text-[#586e75]">{t("currentTarget")}:</span>
              <div className="relative group">
                <select
                  value={activeTask.task_id}
                  onChange={(e) => onSelectTask(e.target.value)}
                  className="bg-[#fdfaf3] border border-[#dfd6bf] hover:border-[#2aa198]/60 rounded-lg px-2.5 py-1 text-xs font-mono text-[#2aa198] font-medium focus:outline-none cursor-pointer appearance-none pr-7 max-w-[200px] truncate shadow-2xs"
                >
                  {tasks.map((t) => (
                    <option key={t.task_id} value={t.task_id}>
                      {t.target.path} · {t.status} · {t.task_id.slice(-6)}
                    </option>
                  ))}
                </select>
                <ChevronDown className="w-3.5 h-3.5 text-[#586e75] absolute right-2 top-2.5 pointer-events-none group-hover:text-[#2aa198]" />
              </div>
            </div>
          )}
        </div>

        {/* Center: Navigation Pill Tabs */}
        <nav className="hidden 2xl:flex items-center gap-1 p-1 rounded-xl bg-[#e6ded0] border border-[#d8ceb8] shrink-0">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all cursor-pointer select-none relative ${
                  isActive
                    ? "bg-[#fdf6e3] text-[#2aa198] border border-[#2aa198]/30 shadow-2xs font-semibold"
                    : "text-[#586e75] hover:text-[#2b3638] hover:bg-[#eee8d5]"
                }`}
              >
                <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? "text-[#2aa198]" : "text-[#839496]"}`} />
                <span>{item.label}</span>
                {item.badge && (
                  <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-[#dfd6bf] text-[#586e75]">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Right: Quick Command Palette & Execution Trigger & Language Switcher */}
        <div className="flex items-center gap-2.5 shrink-0 whitespace-nowrap">
          {/* Language Switcher Button */}
          <button
            onClick={toggleLanguage}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-[#fdfaf3] hover:bg-[#ffffff] border border-[#dfd6bf] text-xs font-mono font-bold transition-colors cursor-pointer shadow-2xs select-none"
            title={language === "zh" ? "Switch to English" : "切换为中文版"}
          >
            <Languages className="w-3.5 h-3.5 text-[#2aa198]" />
            <span className={language === "zh" ? "text-[#2aa198] font-bold" : "text-[#839496]"}>中</span>
            <span className="text-[#dfd6bf]">/</span>
            <span className={language === "en" ? "text-[#2aa198] font-bold" : "text-[#839496]"}>EN</span>
          </button>

          {/* Command Palette Button (⌘K) */}
          <button
            onClick={onOpenCommandPalette}
            className="flex items-center gap-2 px-2.5 py-1.5 rounded-xl bg-[#fdfaf3] hover:bg-[#ffffff] border border-[#dfd6bf] text-xs text-[#586e75] hover:text-[#2b3638] transition-colors cursor-pointer shadow-2xs"
            title="Open Command Palette (Cmd+K / Ctrl+K)"
          >
            <Search className="w-3.5 h-3.5 text-[#586e75]" />
            <span className="hidden sm:inline text-[11px] font-sans">{t("commandPalette")}...</span>
            <kbd className="hidden sm:inline-block px-1.5 py-0.2 text-[9px] font-mono bg-[#eee8d5] text-[#586e75] rounded border border-[#dfd6bf]">
              ⌘K
            </kbd>
          </button>

          {/* Sync / Refresh */}
          <button
            onClick={onRefresh}
            className="p-2 rounded-xl bg-[#fdfaf3] hover:bg-[#ffffff] border border-[#dfd6bf] text-[#586e75] hover:text-[#2b3638] transition-colors cursor-pointer shadow-2xs"
            title={t("refresh")}
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>

          {/* Main Action Trigger */}
          <button
            onClick={onTriggerRun}
            disabled={isRunning || !canRun}
            title={!canRun ? (language === "zh" ? "当前任务已完成；请新建或切换到待执行任务" : "This task has completed; select a new task") : undefined}
            className="px-3.5 py-1.5 rounded-xl bg-[#2aa198] hover:bg-[#238b83] text-white font-bold text-xs flex items-center gap-1.5 whitespace-nowrap transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-xs"
          >
            <Play className={`w-3.5 h-3.5 fill-current ${isRunning ? "animate-spin" : ""}`} />
            <span className="hidden sm:inline">
              {isRunning
                ? t("executingPipeline")
                : !activeTask
                  ? (language === "zh" ? "暂无任务" : "No Task")
                : !canRun
                  ? (language === "zh" ? "审计已完成" : "Audit Complete")
                  : (language === "zh" ? "启动挖掘" : "Run Audit")}
            </span>
          </button>
        </div>
      </div>

      {/* Mobile / Tablet Horizontal Navigation Scrollbar */}
      <div className="2xl:hidden border-t border-[#dfd6bf] overflow-x-auto py-1 px-4 flex items-center gap-1 bg-[#eee8d5]">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium whitespace-nowrap transition-colors cursor-pointer ${
                isActive
                  ? "bg-[#fdf6e3] text-[#2aa198] border border-[#2aa198]/40 font-semibold"
                  : "text-[#586e75] hover:text-[#2b3638]"
              }`}
            >
              <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? "text-[#2aa198]" : "text-[#657b83]"}`} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
