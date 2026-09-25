import { useEffect, useState } from "react";
import { createTask, listTasks, runTask } from "../api";
import type { Task } from "../types";
import { statusStyle } from "../types";

const SUGGESTED_TARGETS = [
  "benchmarks/source/py-cmd-001-vulnerable/app.py",
  "benchmarks/source/py-cmd-002-clean/app.py",
];

export default function Dashboard({
  onOpenTask,
}: {
  onOpenTask: (taskId: string) => void;
}) {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [path, setPath] = useState(SUGGESTED_TARGETS[0]);
  const [type, setType] = useState("source");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);

  const refresh = () => {
    listTasks()
      .then(setTasks)
      .catch((err: unknown) => setError(String(err)));
  };

  useEffect(refresh, []);

  const handleCreate = async () => {
    setError(null);
    setBusy(true);
    try {
      const task = await createTask(path, type);
      await runTask(task.task_id);
      refresh();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleRun = async (taskId: string) => {
    setError(null);
    setRunningId(taskId);
    try {
      await runTask(taskId);
      refresh();
    } catch (err) {
      setError(String(err));
    } finally {
      setRunningId(null);
    }
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-4">
        <h2 className="mb-3 text-base font-semibold text-slate-800">新建任务</h2>
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-sm text-slate-600">
            目标路径
            <input
              className="w-96 rounded-md border border-slate-300 px-3 py-1.5"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              list="targets"
            />
            <datalist id="targets">
              {SUGGESTED_TARGETS.map((t) => (
                <option key={t} value={t} />
              ))}
            </datalist>
          </label>
          <label className="flex flex-col gap-1 text-sm text-slate-600">
            类型
            <select
              className="rounded-md border border-slate-300 px-3 py-1.5"
              value={type}
              onChange={(e) => setType(e.target.value)}
            >
              <option value="source">source</option>
              <option value="binary">binary</option>
              <option value="project">project</option>
            </select>
          </label>
          <button
            className="rounded-md bg-slate-800 px-4 py-2 text-sm text-white disabled:opacity-50"
            onClick={handleCreate}
            disabled={busy}
          >
            {busy ? "创建并运行…" : "创建并运行"}
          </button>
          <p className="text-xs text-slate-400">
            静态分析样本；动态执行仅在授权隔离环境发起
          </p>
        </div>
        {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-base font-semibold text-slate-800">任务列表</h2>
          <button className="text-sm text-slate-500 hover:text-slate-800" onClick={refresh}>
            刷新
          </button>
        </div>
        {tasks.length === 0 ? (
          <p className="py-6 text-center text-sm text-slate-400">暂无任务</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-left text-slate-500">
                <th className="py-2 pr-3">任务</th>
                <th className="pr-3">目标</th>
                <th className="pr-3">状态</th>
                <th className="pr-3">创建时间</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tasks.map((task) => {
                const style = statusStyle(task.status);
                return (
                  <tr key={task.task_id} className="border-b border-slate-100">
                    <td className="py-2 pr-3 font-mono text-xs">{task.task_id}</td>
                    <td className="pr-3 text-xs text-slate-600">{task.target.path}</td>
                    <td className="pr-3">
                      <span className={`rounded-full px-2 py-0.5 text-xs ${style.cls}`}>
                        {style.label}
                      </span>
                    </td>
                    <td className="pr-3 text-xs text-slate-500">
                      {new Date(task.created_at).toLocaleString()}
                    </td>
                    <td className="flex justify-end gap-2">
                      <button
                        className="rounded-md border border-slate-300 px-2 py-1 text-xs hover:bg-slate-50"
                        onClick={() => onOpenTask(task.task_id)}
                      >
                        详情
                      </button>
                      <button
                        className="rounded-md border border-slate-300 px-2 py-1 text-xs hover:bg-slate-50 disabled:opacity-50"
                        onClick={() => handleRun(task.task_id)}
                        disabled={runningId === task.task_id}
                      >
                        {runningId === task.task_id ? "运行中…" : "重新运行"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
