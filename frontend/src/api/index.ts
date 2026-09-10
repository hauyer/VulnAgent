import { apiClient } from './client'
import type {
  HealthResponse,
  Task,
  VulnerabilityCandidate,
  Evidence,
  TraceEvent,
  VerificationResult,
  Report,
} from '@/types'

// ── Health ───────────────────────────────────────────────────────────────────
export const healthApi = {
  get: () => apiClient.get<HealthResponse>('/health'),
}

// ── Tasks ────────────────────────────────────────────────────────────────────
export const tasksApi = {
  list: () => apiClient.get<Task[]>('/tasks'),
  get: (id: string) => apiClient.get<Task>(`/tasks/${id}`),
  create: (body: { target_path: string; target_type: string }) =>
    apiClient.post<Task>('/tasks', body),
  run: (id: string) => apiClient.post<Task>(`/tasks/${id}/run`),
}

// ── Findings ─────────────────────────────────────────────────────────────────
export const findingsApi = {
  listByTask: (taskId: string) =>
    apiClient.get<VulnerabilityCandidate[]>(`/tasks/${taskId}/findings`),
  listAll: async () => {
    try {
      const tasks = await tasksApi.list()
      const results = await Promise.all(
        tasks.map(t => findingsApi.listByTask(t.task_id).catch(() => []))
      )
      return results.flat()
    } catch {
      return []
    }
  },
}

// ── Evidence ─────────────────────────────────────────────────────────────────
export const evidenceApi = {
  listByTask: (taskId: string) =>
    apiClient.get<Evidence[]>(`/tasks/${taskId}/evidence`),
  listAll: async () => {
    try {
      const tasks = await tasksApi.list()
      const results = await Promise.all(
        tasks.map(t => evidenceApi.listByTask(t.task_id).catch(() => []))
      )
      return results.flat()
    } catch {
      return []
    }
  },
}

// ── Trace ─────────────────────────────────────────────────────────────────────
export const traceApi = {
  listByTask: (taskId: string) =>
    apiClient.get<TraceEvent[]>(`/tasks/${taskId}/trace`),
}

// ── Verifications ─────────────────────────────────────────────────────────────
export const verificationsApi = {
  listByTask: (taskId: string) =>
    apiClient.get<VerificationResult[]>(`/tasks/${taskId}/verifications`),
}

// ── Reports ───────────────────────────────────────────────────────────────────
export const reportsApi = {
  getByTask: (taskId: string) =>
    apiClient.get<Report>(`/tasks/${taskId}/report`),
}
