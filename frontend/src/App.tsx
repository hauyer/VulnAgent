import { useState } from "react";
import Dashboard from "./pages/Dashboard";
import TaskDetail from "./pages/TaskDetail";
import Experiments from "./pages/Experiments";

type Route = { name: "dashboard" } | { name: "task"; taskId: string } | { name: "experiments" };

export default function App() {
  const [route, setRoute] = useState<Route>({ name: "dashboard" });

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
          <button
            className="text-lg font-semibold text-slate-800"
            onClick={() => setRoute({ name: "dashboard" })}
          >
            VulnAgent <span className="text-sm font-normal text-slate-500">网络空间安全课程设计</span>
          </button>
          <nav className="flex gap-2">
            <button
              className={`rounded-md px-3 py-1.5 text-sm ${
                route.name === "dashboard" ? "bg-slate-800 text-white" : "text-slate-600 hover:bg-slate-100"
              }`}
              onClick={() => setRoute({ name: "dashboard" })}
            >
              任务
            </button>
            <button
              className={`rounded-md px-3 py-1.5 text-sm ${
                route.name === "experiments" ? "bg-slate-800 text-white" : "text-slate-600 hover:bg-slate-100"
              }`}
              onClick={() => setRoute({ name: "experiments" })}
            >
              实验
            </button>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        {route.name === "dashboard" && (
          <Dashboard onOpenTask={(taskId) => setRoute({ name: "task", taskId })} />
        )}
        {route.name === "task" && (
          <TaskDetail
            taskId={route.taskId}
            onBack={() => setRoute({ name: "dashboard" })}
          />
        )}
        {route.name === "experiments" && <Experiments />}
      </main>
    </div>
  );
}
