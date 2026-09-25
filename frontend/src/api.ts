import type {
  Evidence,
  Finding,
  ReviewNote,
  Task,
  TraceEvent,
  Verification,
} from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status}: ${body.slice(0, 240)}`);
  }
  return (await response.json()) as T;
}

export function listTasks(): Promise<Task[]> {
  return request<Task[]>("/api/tasks");
}

export function getTask(taskId: string): Promise<Task> {
  return request<Task>(`/api/tasks/${taskId}`);
}

export function createTask(targetPath: string, targetType: string): Promise<Task> {
  return request<Task>("/api/tasks", {
    method: "POST",
    body: JSON.stringify({ target_path: targetPath, target_type: targetType }),
  });
}

export function runTask(taskId: string): Promise<Task> {
  return request<Task>(`/api/tasks/${taskId}/run`, { method: "POST" });
}

export function getTrace(taskId: string): Promise<TraceEvent[]> {
  return request<TraceEvent[]>(`/api/tasks/${taskId}/trace`);
}

export function getFindings(taskId: string): Promise<Finding[]> {
  return request<Finding[]>(`/api/tasks/${taskId}/findings`);
}

export function getEvidence(taskId: string): Promise<Evidence[]> {
  return request<Evidence[]>(`/api/tasks/${taskId}/evidence`);
}

export function getVerifications(taskId: string): Promise<Verification[]> {
  return request<Verification[]>(`/api/tasks/${taskId}/verifications`);
}

export function getReviews(taskId: string): Promise<unknown[]> {
  return request<unknown[]>(`/api/tasks/${taskId}/reviews`);
}

export function submitReview(
  taskId: string,
  vulnerabilityId: string,
  review: ReviewNote,
): Promise<unknown> {
  return request(`/api/tasks/${taskId}/findings/${vulnerabilityId}/review`, {
    method: "PUT",
    body: JSON.stringify(review),
  });
}

export interface ExperimentList {
  experiments: string[];
}

export interface ExperimentDetail {
  experiment_id: string;
  summary?: Record<string, unknown>;
  metrics?: Record<string, unknown>;
  candidate_count?: number;
  summary_error?: string;
  metrics_error?: string;
}

export function listExperiments(): Promise<ExperimentList> {
  return request<ExperimentList>("/api/experiments");
}

export function getExperiment(id: string): Promise<ExperimentDetail> {
  return request<ExperimentDetail>(`/api/experiments/${id}`);
}
