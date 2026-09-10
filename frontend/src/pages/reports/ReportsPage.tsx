import { Link } from 'react-router-dom'
import { useTasks, useAllFindings } from '@/hooks'
import { VulnStatusBadge } from '@/components/ui/StatusBadge'
import { Skeleton, EmptyState } from '@/components/ui/Primitives'
import { Topbar } from '@/components/layout/Layout'
import { formatDateTime } from '@/lib/utils'

export default function ReportsPage() {
  const { data: tasks = [], isLoading: tasksLoading } = useTasks()
  const { data: findings = [], isLoading: findingsLoading } = useAllFindings()

  const completed = tasks.filter(t => t.status === 'completed')
  const confirmed = findings.filter(f => f.status === 'CONFIRMED')
  const rejected  = findings.filter(f => f.status === 'REJECTED')

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Topbar
        title="Reports"
        subtitle="Completed task reports — CONFIRMED vulnerabilities require independent verification"
      />

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Global summary */}
        <div className="grid grid-cols-4 gap-0 border border-[hsl(var(--border))] rounded overflow-hidden bg-[hsl(var(--card))]">
          {[
            { label: 'Completed Tasks',    value: completed.length, accent: '' },
            { label: 'Total Findings',     value: findings.length,  accent: '' },
            { label: 'Confirmed',          value: confirmed.length, accent: 'text-[hsl(0_72%_51%)]' },
            { label: 'Rejected',           value: rejected.length,  accent: '' },
          ].map(c => (
            <div key={c.label} className="p-4 border-r border-[hsl(var(--border))] last:border-r-0">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">{c.label}</div>
              {tasksLoading || findingsLoading
                ? <Skeleton className="h-8 w-12 mt-1" />
                : <div className={`text-3xl font-bold font-mono mt-1 ${c.accent || 'text-[hsl(var(--foreground))]'}`}>{c.value}</div>
              }
            </div>
          ))}
        </div>

        {/* Completed tasks list */}
        <div className="space-y-2">
          <h2 className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            Completed Tasks with Reports
          </h2>
          <div className="border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))] overflow-hidden">
            {tasksLoading ? (
              <div className="p-4 space-y-2">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
            ) : completed.length === 0 ? (
              <EmptyState
                title="No completed tasks"
                description="Reports are generated when tasks reach COMPLETED status."
                action={<Link to="/tasks" className="text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150">Go to Tasks</Link>}
              />
            ) : (
              completed.map(t => {
                const taskFindings = findings.filter(f => f.task_id === t.task_id)
                const taskConfirmed = taskFindings.filter(f => f.status === 'CONFIRMED').length
                return (
                  <div key={t.task_id} className="flex items-center gap-4 px-4 py-3 border-b border-[hsl(var(--border))] last:border-b-0 hover:bg-[hsl(var(--accent))] transition-colors duration-150">
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-[hsl(var(--foreground))] truncate">{t.target.path}</div>
                      <div className="text-[11px] font-mono text-[hsl(var(--muted-foreground))] mt-0.5">{t.task_id.slice(0, 8)}… · {formatDateTime(t.created_at)}</div>
                    </div>
                    <div className="flex items-center gap-4 flex-shrink-0 text-[11px] font-mono text-[hsl(var(--muted-foreground))]">
                      <span>{taskFindings.length} findings</span>
                      {taskConfirmed > 0 && (
                        <span className="text-[hsl(0_72%_51%)] font-semibold">{taskConfirmed} confirmed</span>
                      )}
                    </div>
                    <Link
                      to={`/tasks/${t.task_id}?tab=report`}
                      className="text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150 flex-shrink-0"
                    >
                      View Report
                    </Link>
                  </div>
                )
              })
            )}
          </div>
        </div>

        {/* Confirmed vulnerabilities */}
        {confirmed.length > 0 && (
          <div className="space-y-2">
            <h2 className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">Confirmed Vulnerabilities</h2>
            <div className="border border-[hsl(0_72%_51%/0.3)] rounded bg-[hsl(var(--card))] overflow-hidden">
              {confirmed.map(f => (
                <div key={f.vulnerability_id} className="flex items-center gap-4 px-4 py-3 border-b border-[hsl(var(--border))] last:border-b-0 hover:bg-[hsl(var(--accent))] transition-colors duration-150">
                  <VulnStatusBadge status={f.status} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-[hsl(var(--foreground))] truncate">{f.title}</div>
                    <div className="text-[11px] font-mono text-[hsl(var(--muted-foreground))] mt-0.5">{f.cwe_id ?? '—'} · {f.vulnerability_type}</div>
                  </div>
                  <span className="text-[11px] font-mono text-[hsl(var(--muted-foreground))]">{Math.round(f.confidence * 100)}%</span>
                  <Link
                    to={`/tasks/${f.task_id}`}
                    className="text-[10px] px-2 py-1 rounded border border-[hsl(var(--border))] hover:bg-[hsl(var(--accent))] transition-colors duration-150 flex-shrink-0"
                  >
                    Open Task
                  </Link>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
