import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useTasks, useCreateTask, useRunTask } from '@/hooks'
import { TaskStatusBadge } from '@/components/ui/StatusBadge'
import { Skeleton, EmptyState, ErrorState, IdCell } from '@/components/ui/Primitives'
import { Topbar } from '@/components/layout/Layout'
import { formatDateTime, formatDuration } from '@/lib/utils'
import type { Task } from '@/types'

type FilterType = 'ALL' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CREATED'
const RUNNING_STATUSES = new Set(['planning','analyzing','dynamic_testing','profiling','verifying','reporting'])

function filterTasks(tasks: Task[], filter: FilterType) {
  return tasks.filter(t => {
    const s = t.status.toLowerCase()
    switch (filter) {
      case 'RUNNING':   return RUNNING_STATUSES.has(s)
      case 'COMPLETED': return s === 'completed'
      case 'FAILED':    return s === 'failed'
      case 'CREATED':   return s === 'created'
      default:          return true
    }
  })
}

export default function TasksPage() {
  const { data: tasks, isLoading, error, refetch } = useTasks()
  const createTask = useCreateTask()
  const runTask = useRunTask()

  const [filter, setFilter] = useState<FilterType>('ALL')
  const [targetPath, setTargetPath] = useState('')
  const [targetType, setTargetType] = useState<string>('source')
  const [toast, setToast] = useState<string | null>(null)

  function showToast(msg: string) {
    setToast(msg)
    setTimeout(() => setToast(null), 3000)
  }

  async function handleCreate(run: boolean) {
    if (!targetPath.trim()) return
    try {
      const task = await createTask.mutateAsync({ target_path: targetPath.trim(), target_type: targetType })
      if (run) {
        await runTask.mutateAsync(task.task_id)
        showToast(`Task started: ${task.task_id.slice(0, 8)}…`)
      } else {
        showToast(`Task created: ${task.task_id.slice(0, 8)}…`)
      }
      setTargetPath('')
    } catch (e: unknown) {
      showToast(`Failed: ${(e as Error).message}`)
    }
  }

  const taskList = tasks ?? []
  const filtered = filterTasks([...taskList].sort((a, b) => (b.created_at ?? '').localeCompare(a.created_at ?? '')), filter)
  const counts: Record<FilterType, number> = {
    ALL: taskList.length,
    RUNNING: taskList.filter(t => RUNNING_STATUSES.has(t.status)).length,
    COMPLETED: taskList.filter(t => t.status === 'completed').length,
    FAILED: taskList.filter(t => t.status === 'failed').length,
    CREATED: taskList.filter(t => t.status === 'created').length,
  }

  const FILTERS: { key: FilterType; label: string }[] = [
    { key: 'ALL', label: 'All' },
    { key: 'RUNNING', label: 'Running' },
    { key: 'COMPLETED', label: 'Done' },
    { key: 'FAILED', label: 'Failed' },
    { key: 'CREATED', label: 'Queued' },
  ]

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Topbar
        title="Tasks"
        subtitle={`${taskList.length} total analysis tasks`}
        actions={
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150"
            aria-label="Refresh task list"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/>
            </svg>
            Refresh
          </button>
        }
      />

      {/* Create task bar */}
      <div className="flex-shrink-0 border-b border-[hsl(var(--border))] bg-[hsl(var(--card))] px-5 py-3">
        <div className="flex items-end gap-2">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">Type</label>
            <select
              value={targetType}
              onChange={e => setTargetType(e.target.value)}
              className="h-8 px-2 text-xs rounded border border-[hsl(var(--input))] bg-[hsl(var(--background))] text-[hsl(var(--foreground))] outline-none focus:border-[hsl(var(--ring))] focus:ring-1 focus:ring-[hsl(var(--ring)/0.2)] transition-all duration-150 cursor-pointer"
            >
              <option value="source">Source</option>
              <option value="binary">Binary</option>
              <option value="project">Project</option>
              <option value="archive">Archive</option>
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">Target path</label>
            <input
              type="text"
              value={targetPath}
              onChange={e => setTargetPath(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleCreate(true) }}
              placeholder="e.g. tests/fixtures/sample"
              className="h-8 px-3 text-xs rounded border border-[hsl(var(--input))] bg-[hsl(var(--background))] text-[hsl(var(--foreground))] placeholder-[hsl(var(--muted-foreground))] outline-none focus:border-[hsl(var(--ring))] focus:ring-1 focus:ring-[hsl(var(--ring)/0.2)] transition-all duration-150"
            />
          </div>
          <div className="flex gap-1.5 pb-0">
            <button
              onClick={() => handleCreate(false)}
              disabled={!targetPath.trim() || createTask.isPending}
              className="h-8 px-3 text-xs rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150"
            >
              Create
            </button>
            <button
              onClick={() => handleCreate(true)}
              disabled={!targetPath.trim() || createTask.isPending || runTask.isPending}
              className="h-8 px-4 text-xs rounded bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-150 font-medium"
            >
              {(createTask.isPending || runTask.isPending) ? 'Starting…' : 'Create & Run'}
            </button>
          </div>
        </div>
        {/* Preset chips */}
        <div className="flex items-center gap-1.5 mt-2">
          <span className="text-[10px] text-[hsl(var(--muted-foreground))]">Presets:</span>
          {[
            { path: 'tests/fixtures/sample', type: 'source' },
            { path: 'sample.c', type: 'source' },
            { path: 'sample.elf', type: 'binary' },
            { path: 'benchmarks/cwe_sample', type: 'project' },
          ].map(p => (
            <button
              key={p.path}
              onClick={() => { setTargetPath(p.path); setTargetType(p.type) }}
              className="text-[10px] font-mono px-2 py-0.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] hover:border-[hsl(var(--ring)/0.4)] transition-all duration-150"
            >
              {p.path}
            </button>
          ))}
        </div>
      </div>

      {/* Filter tabs */}
      <div className="flex border-b border-[hsl(var(--border))] flex-shrink-0 bg-[hsl(var(--background))] overflow-x-auto">
        {FILTERS.map(f => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className={`flex items-center gap-1.5 px-4 py-2 text-xs font-medium border-b-2 transition-all duration-150 whitespace-nowrap ${
              filter === f.key
                ? 'border-[hsl(var(--ring))] text-[hsl(var(--foreground))]'
                : 'border-transparent text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]'
            }`}
          >
            {f.label}
            <span className={`font-mono text-[10px] px-1 rounded border ${
              filter === f.key
                ? 'bg-[hsl(var(--ring)/0.15)] text-[hsl(var(--ring))] border-[hsl(var(--ring)/0.3)]'
                : 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]'
            }`}>
              {counts[f.key]}
            </span>
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        {isLoading ? (
          <div className="p-5 space-y-2">
            {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-11 w-full" />)}
          </div>
        ) : error ? (
          <ErrorState message="Failed to load task list." onRetry={() => refetch()} />
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>}
            title={filter === 'ALL' ? 'No tasks yet' : `No ${filter.toLowerCase()} tasks`}
            description="Create a new analysis task using the form above."
          />
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-[hsl(var(--card))] border-b border-[hsl(var(--border))]">
              <tr>
                {['Task ID','Target','Type','Status','Created At','Duration','Action'].map(h => (
                  <th key={h} className="text-left px-4 py-2.5 font-semibold text-[hsl(var(--muted-foreground))] uppercase tracking-wider text-[10px] whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[hsl(var(--border))]">
              {filtered.map(task => (
                <tr
                  key={task.task_id}
                  className="hover:bg-[hsl(var(--accent))] transition-colors duration-150 group"
                >
                  <td className="px-4 py-2.5"><IdCell id={task.task_id} /></td>
                  <td className="px-4 py-2.5 font-medium text-[hsl(var(--foreground))] max-w-[200px] truncate" title={task.target.path}>{task.target.path}</td>
                  <td className="px-4 py-2.5 font-mono text-[hsl(var(--muted-foreground))] uppercase">{task.target.target_type}</td>
                  <td className="px-4 py-2.5"><TaskStatusBadge status={task.status} /></td>
                  <td className="px-4 py-2.5 text-[hsl(var(--muted-foreground))] font-mono whitespace-nowrap">{formatDateTime(task.created_at)}</td>
                  <td className="px-4 py-2.5 text-[hsl(var(--muted-foreground))] font-mono">{formatDuration(task.created_at, task.completed_at)}</td>
                  <td className="px-4 py-2.5">
                    <Link
                      to={`/tasks/${task.task_id}`}
                      className="text-xs px-2 py-1 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150"
                    >
                      Open
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-5 right-5 bg-[hsl(var(--popover))] border border-[hsl(var(--border))] rounded px-4 py-2.5 text-sm text-[hsl(var(--foreground))] shadow-lg z-50 animate-in fade-in slide-in-from-bottom-2 duration-150">
          {toast}
        </div>
      )}
    </div>
  )
}
