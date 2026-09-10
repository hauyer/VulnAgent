import { Link } from 'react-router-dom'
import { useTasks, useAllFindings } from '@/hooks'
import { TaskStatusBadge, VulnStatusBadge } from '@/components/ui/StatusBadge'
import { Skeleton, EmptyState, ErrorState } from '@/components/ui/Primitives'
import { Topbar } from '@/components/layout/Layout'
import { formatDateTime, formatDuration } from '@/lib/utils'
import type { Task, VulnerabilityCandidate } from '@/types'

// ── Metric Card ───────────────────────────────────────────────────────────────
function MetricCard({
  label, value, sub, accent,
}: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="flex flex-col gap-1 p-4 border-r border-[hsl(var(--border))] last:border-r-0">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">{label}</span>
      <span className={`text-3xl font-bold font-mono leading-none ${accent ?? 'text-[hsl(var(--foreground))]'}`}>{value}</span>
      {sub && <span className="text-[11px] text-[hsl(var(--muted-foreground))]">{sub}</span>}
    </div>
  )
}

// ── Agent Runtime Overview ─────────────────────────────────────────────────────
const AGENTS = [
  { id: 'planner',      name: 'Planner' },
  { id: 'source_audit', name: 'Source Audit' },
  { id: 'binary',       name: 'Binary Analysis' },
  { id: 'fuzz',         name: 'Fuzz' },
  { id: 'verification', name: 'Verification' },
  { id: 'reviewer',     name: 'Reviewer' },
  { id: 'report',       name: 'Report' },
]

function RuntimeOverview({ tasks }: { tasks: Task[] }) {
  // Derive which agents have been "touched" from task statuses
  const running = tasks.filter(t =>
    ['planning','analyzing','dynamic_testing','profiling','verifying','reporting'].includes(t.status)
  ).length
  const completed = tasks.filter(t => t.status === 'completed').length

  return (
    <div className="grid grid-cols-7 divide-x divide-[hsl(var(--border))] border border-[hsl(var(--border))] rounded">
      {AGENTS.map((agent) => {
        let dotClass = 'bg-[hsl(var(--muted-foreground))] opacity-30'
        let labelClass = 'text-[hsl(var(--muted-foreground))]'
        let status = 'Idle'

        if (running > 0) {
          dotClass = 'bg-[hsl(201_94%_40%)] animate-pulse'
          labelClass = 'text-[hsl(201_94%_40%)]'
          status = 'Active'
        } else if (completed > 0) {
          dotClass = 'bg-[hsl(145_63%_40%)]'
          labelClass = 'text-[hsl(145_63%_40%)]'
          status = 'Ready'
        }

        return (
          <div key={agent.id} className="flex flex-col items-center gap-2 p-3 text-center">
            <span className={`w-2.5 h-2.5 rounded-full ${dotClass}`} />
            <span className="text-[10px] font-semibold text-[hsl(var(--foreground))] leading-tight">{agent.name}</span>
            <span className={`text-[9px] font-mono ${labelClass}`}>{status}</span>
          </div>
        )
      })}
    </div>
  )
}

// ── Recent Tasks ───────────────────────────────────────────────────────────────
function RecentTaskRow({ task }: { task: Task }) {
  return (
    <div className="flex items-center gap-3 px-4 py-2.5 border-b border-[hsl(var(--border))] last:border-b-0 hover:bg-[hsl(var(--accent))] transition-colors duration-150">
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-[hsl(var(--foreground))] truncate">{task.target.path}</div>
        <div className="text-[11px] text-[hsl(var(--muted-foreground))] font-mono mt-0.5">{task.task_id.slice(0, 8)}… · {formatDateTime(task.created_at)}</div>
      </div>
      <span className="text-[11px] font-mono text-[hsl(var(--muted-foreground))] uppercase">{task.target.target_type}</span>
      <TaskStatusBadge status={task.status} />
      <span className="text-[11px] text-[hsl(var(--muted-foreground))] font-mono w-12 text-right">{formatDuration(task.created_at, task.completed_at)}</span>
      <Link
        to={`/tasks/${task.task_id}`}
        className="text-xs px-2 py-1 border border-[hsl(var(--border))] rounded bg-[hsl(var(--secondary))] text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors duration-150"
      >
        Open
      </Link>
    </div>
  )
}

// ── Main Dashboard ─────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const { data: tasks, isLoading: tasksLoading, error: tasksError, refetch } = useTasks()
  const { data: findings } = useAllFindings()

  const taskList: Task[] = tasks ?? []
  const findingList: VulnerabilityCandidate[] = findings ?? []

  const running   = taskList.filter(t => ['planning','analyzing','dynamic_testing','profiling','verifying','reporting'].includes(t.status)).length
  const confirmed = findingList.filter(f => f.status === 'CONFIRMED').length
  const recent    = [...taskList].sort((a, b) => (b.created_at ?? '').localeCompare(a.created_at ?? '')).slice(0, 8)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Topbar
        title="Dashboard"
        subtitle="VulnAgent AI Security Analysis Console"
        actions={
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors duration-150"
            aria-label="Refresh dashboard"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/>
            </svg>
            Refresh
          </button>
        }
      />

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Metrics */}
        {tasksLoading ? (
          <div className="grid grid-cols-4 gap-0 border border-[hsl(var(--border))] rounded overflow-hidden">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="p-4 border-r border-[hsl(var(--border))] last:border-r-0 space-y-2">
                <Skeleton className="h-3 w-20" />
                <Skeleton className="h-8 w-12" />
              </div>
            ))}
          </div>
        ) : tasksError ? (
          <ErrorState message="Failed to load task metrics." onRetry={() => refetch()} />
        ) : (
          <div className="grid grid-cols-4 gap-0 border border-[hsl(var(--border))] rounded overflow-hidden bg-[hsl(var(--card))]">
            <MetricCard label="Total Tasks" value={taskList.length} sub="All-time" />
            <MetricCard label="Running" value={running} sub="In progress" accent={running > 0 ? 'text-[hsl(201_94%_40%)]' : undefined} />
            <MetricCard label="Total Findings" value={findingList.length} sub="Candidates" />
            <MetricCard label="Confirmed" value={confirmed} sub="Verified vulns" accent={confirmed > 0 ? 'text-[hsl(0_72%_51%)]' : undefined} />
          </div>
        )}

        {/* Runtime Overview */}
        <div className="space-y-2">
          <h2 className="text-xs font-semibold text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Agent Runtime Overview</h2>
          {tasksLoading ? (
            <Skeleton className="h-20 w-full" />
          ) : (
            <RuntimeOverview tasks={taskList} />
          )}
        </div>

        {/* Recent Tasks */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold text-[hsl(var(--muted-foreground))] uppercase tracking-wider">Recent Tasks</h2>
            <Link to="/tasks" className="text-xs text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors duration-150">
              View all →
            </Link>
          </div>
          <div className="border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))] overflow-hidden">
            {tasksLoading ? (
              <div className="p-4 space-y-2">
                {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}
              </div>
            ) : recent.length === 0 ? (
              <EmptyState
                title="No tasks yet"
                description="Create an analysis task to get started."
                action={
                  <Link to="/tasks" className="text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150">
                    Go to Tasks
                  </Link>
                }
              />
            ) : (
              recent.map(t => <RecentTaskRow key={t.task_id} task={t} />)
            )}
          </div>
        </div>

        {/* Key innovation callout */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { title: 'Multi-Agent Routing', desc: 'Bounded supervisor routes tasks between specialized agents with max-step limits and retry controls.' },
            { title: 'Evidence-First Chain', desc: 'Every finding must carry verifiable evidence. MODEL_REASONING_SUMMARY alone cannot confirm a vulnerability.' },
            { title: 'Independent Verification', desc: 'Discovery and Verification agents are fully decoupled. Only the Verification layer can produce CONFIRMED status.' },
          ].map(card => (
            <div key={card.title} className="p-4 border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))]">
              <p className="text-xs font-semibold text-[hsl(var(--foreground))] mb-1.5">{card.title}</p>
              <p className="text-[11px] text-[hsl(var(--muted-foreground))] leading-relaxed">{card.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
