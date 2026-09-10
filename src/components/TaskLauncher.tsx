import React, { useState } from "react";
import { Play, Sparkles, FolderCode, Binary, Layers, AlertCircle } from "lucide-react";
import { TargetType } from "../types.js";

interface TaskLauncherProps {
  onTaskCreated: (taskId: string) => void;
}

const PRESET_TARGETS = [
  {
    name: "C Daemon Stack Overflow",
    path: "samples/c_buffer_overflow/vuln_server.c",
    type: "source" as TargetType,
    desc: "Unbounded strcpy() stack frame overwrite & return address hijack",
  },
  {
    name: "Python SQL Injection",
    path: "samples/python_sql_injection/app.py",
    type: "source" as TargetType,
    desc: "Direct HTTP string interpolation into database execute query sink",
  },
  {
    name: "x86_64 ELF Binary Crackme",
    path: "samples/binary_auth_bypass/crackme.elf",
    type: "binary" as TargetType,
    desc: "Missing stack canary & bounded check bypass in parse_packet()",
  },
];

export const TaskLauncher: React.FC<TaskLauncherProps> = ({ onTaskCreated }) => {
  const [targetPath, setTargetPath] = useState(PRESET_TARGETS[0].path);
  const [targetType, setTargetType] = useState<TargetType>("source");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreateAndRun = async (path: string, type: TargetType) => {
    setIsSubmitting(true);
    setError(null);
    try {
      // 1. Create Task
      const createRes = await fetch("/api/tasks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_path: path,
          target_type: type,
        }),
      });

      if (!createRes.ok) {
        throw new Error(`Failed to create task: ${createRes.statusText}`);
      }

      const newTask = await createRes.json();
      const taskId = newTask.task_id;

      // 2. Launch Orchestration
      const runRes = await fetch(`/api/tasks/${taskId}/run`, {
        method: "POST",
      });

      if (!runRes.ok) {
        throw new Error(`Pipeline run failed: ${runRes.statusText}`);
      }

      onTaskCreated(taskId);
    } catch (err: any) {
      setError(err.message || "Execution error");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl relative overflow-hidden">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            Launch Autonomous Vulnerability Scan
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Orchestrates Planner, Audit, Fuzz, and Independent Verification agents
          </p>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-rose-950/50 border border-rose-800/80 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Preset Buttons */}
      <div className="mb-4">
        <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-2">
          Target Benchmarks
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          {PRESET_TARGETS.map((preset) => (
            <button
              key={preset.path}
              type="button"
              onClick={() => {
                setTargetPath(preset.path);
                setTargetType(preset.type);
              }}
              className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                targetPath === preset.path
                  ? "bg-cyan-950/40 border-cyan-500/50 text-cyan-200 ring-1 ring-cyan-500/20"
                  : "bg-slate-950/50 border-slate-800 hover:border-slate-700 text-slate-300"
              }`}
            >
              <div className="flex items-center gap-1.5 text-xs font-medium">
                {preset.type === "binary" ? (
                  <Binary className="w-3.5 h-3.5 text-amber-400" />
                ) : (
                  <FolderCode className="w-3.5 h-3.5 text-cyan-400" />
                )}
                <span>{preset.name}</span>
              </div>
              <p className="text-[11px] text-slate-400 line-clamp-1 mt-1 font-mono">{preset.path}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Custom Input Form */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (targetPath) {
            handleCreateAndRun(targetPath, targetType);
          }
        }}
        className="flex flex-col sm:flex-row gap-3 items-end"
      >
        <div className="flex-1 w-full">
          <label className="text-xs text-slate-400 block mb-1">Target File or Binary Path</label>
          <input
            type="text"
            value={targetPath}
            onChange={(e) => setTargetPath(e.target.value)}
            placeholder="e.g. src/api/auth.py or bin/target.elf"
            className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
            required
          />
        </div>

        <div className="w-full sm:w-44">
          <label className="text-xs text-slate-400 block mb-1">Target Analysis Type</label>
          <select
            value={targetType}
            onChange={(e) => setTargetType(e.target.value as TargetType)}
            className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
          >
            <option value="source">Source Code (.c, .py, .go)</option>
            <option value="binary">Binary (ELF, PE, Mach-O)</option>
            <option value="project">Project Workspace</option>
            <option value="archive">Zip Archive (.tar.gz)</option>
          </select>
        </div>

        <button
          type="submit"
          disabled={isSubmitting || !targetPath}
          className="w-full sm:w-auto px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-slate-950 font-semibold text-xs flex items-center justify-center gap-2 transition-all shadow-md shadow-cyan-900/30 disabled:opacity-50 cursor-pointer h-[38px]"
        >
          {isSubmitting ? (
            <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
          ) : (
            <Play className="w-3.5 h-3.5 fill-current" />
          )}
          <span>{isSubmitting ? "Orchestrating..." : "Launch Audit"}</span>
        </button>
      </form>
    </div>
  );
};
