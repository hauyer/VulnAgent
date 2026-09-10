import React, { useState, useEffect } from "react";
import {
  Search,
  Terminal,
  FileCode,
  Shield,
  Activity,
  Layers,
  Sparkles,
  FileText,
  X,
  Play,
  ArrowRight,
  Database,
} from "lucide-react";
import { ActiveTab, Task } from "../types.js";

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectTab: (tab: ActiveTab) => void;
  onSelectTask: (taskId: string) => void;
  onTriggerRun: () => void;
  tasks: Task[];
  activeTask?: Task;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onSelectTab,
  onSelectTask,
  onTriggerRun,
  tasks,
  activeTask,
}) => {
  const [query, setQuery] = useState("");

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        if (isOpen) onClose();
      }
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const NAVIGATION_ITEMS: { id: ActiveTab; label: string; icon: any; category: string }[] = [
    { id: "dashboard", label: "Mission Control Dashboard", icon: Sparkles, category: "Views" },
    { id: "topology", label: "Multi-Agent DAG Topology Graph", icon: Layers, category: "Views" },
    { id: "evidence", label: "Evidence Chain Matrix & Code Inspector", icon: Database, category: "Views" },
    { id: "vulnerabilities", label: "Vulnerability Dossier & Verification", icon: Shield, category: "Views" },
    { id: "report", label: "Executive Security Audit Report", icon: FileText, category: "Views" },
    { id: "trace", label: "Live Domain Event Stream & Telemetry", icon: Activity, category: "Views" },
    { id: "api", label: "REST API Explorer & CLI Console", icon: Terminal, category: "Developer" },
  ];

  const filteredNav = NAVIGATION_ITEMS.filter((item) =>
    item.label.toLowerCase().includes(query.toLowerCase())
  );

  const filteredTasks = tasks.filter((t) =>
    t.target.path.toLowerCase().includes(query.toLowerCase()) ||
    t.task_id.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-[#2b3638]/40 backdrop-blur-sm animate-in fade-in duration-100">
      <div
        className="w-full max-w-2xl bg-[#fdfaf3] border border-[#dfd6bf] rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[75vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Header */}
        <div className="p-3.5 border-b border-[#dfd6bf] flex items-center gap-3 bg-[#f5eed9]">
          <Search className="w-5 h-5 text-[#2aa198] shrink-0" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command, search targets, or switch views... (Esc to exit)"
            className="w-full bg-transparent border-none text-sm text-[#2b3638] placeholder:text-[#839496] focus:outline-none font-sans"
            autoFocus
          />
          <kbd className="hidden sm:inline-block px-2 py-0.5 text-[10px] font-mono bg-[#eee8d5] text-[#586e75] rounded border border-[#dfd6bf]">
            ESC
          </kbd>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-[#e6deca] text-[#839496] hover:text-[#2b3638] transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-3 font-sans">
          {/* Quick Action */}
          <div className="p-1">
            <span className="text-[10px] font-semibold text-[#586e75] uppercase tracking-wider px-2 block mb-1">
              Quick Actions
            </span>
            <button
              onClick={() => {
                onTriggerRun();
                onClose();
              }}
              className="w-full flex items-center justify-between p-2.5 rounded-lg hover:bg-[#eef7f6] hover:border-[#2aa198]/40 border border-transparent text-left transition-colors group cursor-pointer text-xs text-[#2b3638]"
            >
              <div className="flex items-center gap-2.5">
                <div className="w-6 h-6 rounded-md bg-[#2aa198]/20 text-[#2aa198] flex items-center justify-center">
                  <Play className="w-3 h-3 fill-current" />
                </div>
                <div>
                  <span className="font-semibold text-[#2b3638]">Re-Execute Autonomous Pipeline</span>
                  <span className="text-[11px] text-[#586e75] block">
                    Trigger Planner, Source/Binary Audit, Fuzz, and Verification on current target
                  </span>
                </div>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-[#839496] group-hover:text-[#2aa198] transition-transform group-hover:translate-x-1" />
            </button>
          </div>

          {/* Navigation Views */}
          {filteredNav.length > 0 && (
            <div className="p-1 border-t border-[#dfd6bf] pt-2">
              <span className="text-[10px] font-semibold text-[#586e75] uppercase tracking-wider px-2 block mb-1">
                Workspace Views
              </span>
              <div className="space-y-1">
                {filteredNav.map((item) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.id}
                      onClick={() => {
                        onSelectTab(item.id);
                        onClose();
                      }}
                      className="w-full flex items-center justify-between p-2 rounded-lg hover:bg-[#f5eed9] text-left transition-colors group cursor-pointer text-xs text-[#2b3638]"
                    >
                      <div className="flex items-center gap-2.5">
                        <Icon className="w-4 h-4 text-[#2aa198] group-hover:scale-110 transition-transform" />
                        <span className="font-medium text-[#2b3638]">{item.label}</span>
                      </div>
                      <span className="text-[10px] font-mono text-[#839496] group-hover:text-[#2aa198]">
                        Jump →
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Target Tasks */}
          {filteredTasks.length > 0 && (
            <div className="p-1 border-t border-[#dfd6bf] pt-2">
              <span className="text-[10px] font-semibold text-[#586e75] uppercase tracking-wider px-2 block mb-1">
                Audit Tasks ({tasks.length})
              </span>
              <div className="space-y-1">
                {filteredTasks.map((t) => (
                  <button
                    key={t.task_id}
                    onClick={() => {
                      onSelectTask(t.task_id);
                      onClose();
                    }}
                    className={`w-full flex items-center justify-between p-2 rounded-lg text-left transition-colors cursor-pointer text-xs ${
                      activeTask?.task_id === t.task_id
                        ? "bg-[#eef7f6] border border-[#2aa198] text-[#2b3638] font-medium"
                        : "hover:bg-[#f5eed9] text-[#586e75]"
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <FileCode className="w-3.5 h-3.5 text-[#2aa198]" />
                      <span className="font-mono text-xs text-[#2b3638]">{t.target.path}</span>
                    </div>
                    <div className="flex items-center gap-2 font-mono text-[10px]">
                      <span className="text-[#839496]">{t.target.target_type}</span>
                      <span className="px-1.5 py-0.5 rounded bg-[#eee8d5] text-[#586e75] border border-[#dfd6bf]">
                        {t.status}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer info */}
        <div className="p-2.5 border-t border-[#dfd6bf] bg-[#f5eed9] flex items-center justify-between text-[11px] text-[#586e75] px-4 font-mono">
          <div className="flex items-center gap-2">
            <span>Navigation: ↑↓ Enter</span>
            <span>&bull;</span>
            <span>Esc to dismiss</span>
          </div>
          <span className="text-[#2aa198] font-semibold">VulnAgent OS v0.2.0</span>
        </div>
      </div>
    </div>
  );
};
