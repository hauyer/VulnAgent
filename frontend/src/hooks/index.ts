// ==========================================================================
// TanStack Query hooks — server state management
// Components MUST use these hooks; never call api modules directly.
// ==========================================================================

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  healthApi,
  tasksApi,
  findingsApi,
  evidenceApi,
  traceApi,
  verificationsApi,
  reportsApi,
} from '@/api'

// ── Query Keys ───────────────────────────────────────────────────────────────
export const qk = {
  health:                () => ['health'] as const,
  tasks:                 () => ['tasks'] as const,
  task:          (id: string) => ['tasks', id] as const,
  taskFindings:  (id: string) => ['tasks', id, 'findings'] as const,
  taskEvidence:  (id: string) => ['tasks', id, 'evidence'] as const,
  taskTrace:     (id: string) => ['tasks', id, 'trace'] as const,
  taskVerifs:    (id: string) => ['tasks', id, 'verifications'] as const,
  taskReport:    (id: string) => ['tasks', id, 'report'] as const,
  allFindings:           () => ['findings'] as const,
  allEvidence:           () => ['evidence'] as const,
}

// ── Health ───────────────────────────────────────────────────────────────────
export function useHealth() {
  return useQuery({
    queryKey: qk.health(),
    queryFn: healthApi.get,
    refetchInterval: 10_000,
    retry: false,
  })
}

// ── Tasks ────────────────────────────────────────────────────────────────────
export function useTasks() {
  return useQuery({
    queryKey: qk.tasks(),
    queryFn: tasksApi.list,
    refetchInterval: 3_000,
  })
}

export function useTask(taskId: string | undefined) {
  return useQuery({
    queryKey: qk.task(taskId!),
    queryFn: () => tasksApi.get(taskId!),
    enabled: !!taskId,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      const running = ['planning', 'analyzing', 'dynamic_testing',
                       'profiling', 'verifying', 'reporting'].includes(status ?? '')
      return running ? 1_500 : false
    },
  })
}

export function useCreateTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { target_path: string; target_type: string }) =>
      tasksApi.create(body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: qk.tasks() }) },
  })
}

export function useRunTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (taskId: string) => tasksApi.run(taskId),
    onSuccess: (_, taskId) => {
      qc.invalidateQueries({ queryKey: qk.task(taskId) })
      qc.invalidateQueries({ queryKey: qk.tasks() })
    },
  })
}

// ── Task sub-resources ────────────────────────────────────────────────────────
function isRunning(status?: string) {
  return ['planning', 'analyzing', 'dynamic_testing', 'profiling',
          'verifying', 'reporting'].includes(status ?? '')
}

export function useTaskFindings(taskId: string | undefined, taskStatus?: string) {
  return useQuery({
    queryKey: qk.taskFindings(taskId!),
    queryFn: () => findingsApi.listByTask(taskId!),
    enabled: !!taskId,
    refetchInterval: isRunning(taskStatus) ? 2_000 : false,
  })
}

export function useTaskEvidence(taskId: string | undefined, taskStatus?: string) {
  return useQuery({
    queryKey: qk.taskEvidence(taskId!),
    queryFn: () => evidenceApi.listByTask(taskId!),
    enabled: !!taskId,
    refetchInterval: isRunning(taskStatus) ? 2_000 : false,
  })
}

export function useTaskTrace(taskId: string | undefined, taskStatus?: string) {
  return useQuery({
    queryKey: qk.taskTrace(taskId!),
    queryFn: () => traceApi.listByTask(taskId!),
    enabled: !!taskId,
    refetchInterval: isRunning(taskStatus) ? 1_500 : false,
  })
}

export function useTaskVerifications(taskId: string | undefined, taskStatus?: string) {
  return useQuery({
    queryKey: qk.taskVerifs(taskId!),
    queryFn: () => verificationsApi.listByTask(taskId!),
    enabled: !!taskId,
    refetchInterval: isRunning(taskStatus) ? 2_000 : false,
  })
}

export function useTaskReport(taskId: string | undefined) {
  return useQuery({
    queryKey: qk.taskReport(taskId!),
    queryFn: () => reportsApi.getByTask(taskId!),
    enabled: !!taskId,
    retry: false,
  })
}

// ── All-tasks sub-resources ───────────────────────────────────────────────────
export function useAllFindings() {
  return useQuery({
    queryKey: qk.allFindings(),
    queryFn: findingsApi.listAll,
  })
}

export function useAllEvidence() {
  return useQuery({
    queryKey: qk.allEvidence(),
    queryFn: evidenceApi.listAll,
  })
}
