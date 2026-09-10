import { Router, Request, Response } from "express";
import { db } from "./db.js";
import { orchestrator } from "./orchestrator.js";
import { Target, TargetType, Task } from "../src/types.js";

export const apiRouter = Router();

// Health Check
apiRouter.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", service: "vulnagent" });
});

// Create Task
apiRouter.post("/tasks", (req: Request, res: Response) => {
  const { target_path, target_type, language, file_format, metadata } = req.body || {};

  if (!target_path || !target_type) {
    return res.status(422).json({
      detail: [{ loc: ["body", "target_path"], msg: "target_path and target_type are required" }],
    });
  }

  const validTypes: TargetType[] = ["source", "binary", "project", "archive"];
  const resolvedType = validTypes.includes(target_type) ? (target_type as TargetType) : "source";

  const taskId = `task-${Math.random().toString(36).substring(2, 9)}-${Date.now().toString(36)}`;
  const targetId = `target-${Math.random().toString(36).substring(2, 9)}`;

  const target: Target = {
    target_id: targetId,
    path: target_path,
    target_type: resolvedType,
    language: language || (target_path.endsWith(".c") ? "C" : target_path.endsWith(".py") ? "Python" : "Unknown"),
    file_format: file_format || null,
    metadata: metadata || {},
  };

  const newTask: Task = {
    task_id: taskId,
    target,
    status: "created",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    error: null,
    metadata: {},
  };

  db.tasks.set(taskId, newTask);
  return res.status(201).json(newTask);
});

// List Tasks
apiRouter.get("/tasks", (_req: Request, res: Response) => {
  const allTasks = Array.from(db.tasks.values()).sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  );
  return res.json(allTasks);
});

// Get Single Task
apiRouter.get("/tasks/:task_id", (req: Request, res: Response) => {
  const task = db.tasks.get(req.params.task_id);
  if (!task) {
    return res.status(404).json({ detail: "Task not found" });
  }
  return res.json(task);
});

// Run Task (Orchestrate)
apiRouter.post("/tasks/:task_id/run", async (req: Request, res: Response) => {
  const taskId = req.params.task_id;
  const task = db.tasks.get(taskId);
  if (!task) {
    return res.status(404).json({ detail: "Task not found" });
  }

  try {
    const completedTask = await orchestrator.run(taskId);
    return res.status(200).json(completedTask);
  } catch (err: any) {
    return res.status(500).json({ detail: err.message || "Pipeline execution failed" });
  }
});

// List Task Events
apiRouter.get("/tasks/:task_id/events", (req: Request, res: Response) => {
  const taskId = req.params.task_id;
  if (!db.tasks.has(taskId)) {
    return res.status(404).json({ detail: "Task not found" });
  }
  const events = db.events.get(taskId) || [];
  return res.json(events);
});

// Compatibility-Friendly Trace Resource
apiRouter.get("/tasks/:task_id/trace", (req: Request, res: Response) => {
  const taskId = req.params.task_id;
  if (!db.tasks.has(taskId)) {
    return res.status(404).json({ detail: "Task not found" });
  }
  const events = db.events.get(taskId) || [];
  return res.json(events);
});

// Get Vulnerability Findings
apiRouter.get("/tasks/:task_id/findings", (req: Request, res: Response) => {
  const taskId = req.params.task_id;
  if (!db.tasks.has(taskId)) {
    return res.status(404).json({ detail: "Task not found" });
  }
  const findings = db.findings.get(taskId) || [];
  return res.json(findings);
});

// Get Evidence Chain
apiRouter.get("/tasks/:task_id/evidence", (req: Request, res: Response) => {
  const taskId = req.params.task_id;
  if (!db.tasks.has(taskId)) {
    return res.status(404).json({ detail: "Task not found" });
  }
  const evidence = db.evidence.get(taskId) || [];
  return res.json(evidence);
});

// Get Report
apiRouter.get("/tasks/:task_id/report", (req: Request, res: Response) => {
  const taskId = req.params.task_id;
  if (!db.tasks.has(taskId)) {
    return res.status(404).json({ detail: "Task not found" });
  }
  const reports = db.reports.get(taskId) || [];
  if (reports.length === 0) {
    return res.status(404).json({ detail: "Report not generated" });
  }
  return res.json(reports[reports.length - 1]);
});
