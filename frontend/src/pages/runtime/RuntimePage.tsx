import { useTasks, useTaskTrace } from '@/hooks'
import { Topbar } from '@/components/layout/Layout'
import { TaskStatusBadge, AgentStatusDot } from '@/components/ui/StatusBadge'
import { Skeleton, EmptyState } from '@/components/ui/Primitives'
import { Link } from 'react-router-dom'
import { formatTime } from '@/lib/utils'

const AGENT_NODES = [
  { id: 'planner',            name: 'Planner',          desc: 'Task decomposition & routing' },
  { id: 'source_audit',       name: 'Source Audit',     desc: 'AST / CFG / taint analysis' },
  { id: 'binary_analysis',    name: 'Binary Analysis',  desc: 'Disassembly / CFG / PE-ELF' },
  { id: 'fuzz_agent',         name: 'Fuzz',             desc: 'Seed mutation / crash analysis' },
  { id: 'verification_agent', name: 'Verification',     desc: 'Independent verdict engine' },
  { id: 'reviewer_agent',     name: 'Reviewer',         desc: 'Second-pass high-risk review' },
  { id: 'report_agent',       name: 'Report',           desc: 'Evidence chain + report' },
]

export default function RuntimePage() {
  const { data: tasks, isLoading } = useTasks()
  const taskList = tasks ?? []
  const running = taskList.filter(t =>
    ['planning','analyzing','dynamic_testing','profiling','verifying','reporting'].includes(t.status)
  )
  const recent = [...taskList].sort((a, b) =>
    (b.created_at ?? '').localeCompare(a.created_at ?? '')
  ).slice(0, 1)
  const currentTaskId = running[0]?.task_id ?? recent[0]?.task_id
  const currentTask = running[0] ?? recent[0]

  const { data: trace = [] } = useTaskTrace(currentTaskId, currentTask?.status)
  const agentsDone    = new Set(trace.filter(e => e.event_type === 'AGENT_COMPLETED').map(e => e.sender ?? ''))
  const agentsRunning = new Set(trace.filter(e => e.event_type === 'AGENT_STARTED' && !agentsDone.has(e.sender ?? '')).map(e => e.sender ?? ''))
  const routeCounts   = trace.filter(e => e.event_type === 'AGENT_ROUTED').reduce<Record<string, number>>((acc, e) => {
    acc[e.receiver ?? '?'] = (acc[e.receiver ?? '?'] ?? 0) + 1; return acc
  }, {})

  function getStatus(id: string): string {
    if (agentsRunning.has(id)) return 'running'
    if (agentsDone.has(id))    return 'completed'
    return 'pending'
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Topbar
        title="Agent Runtime"
        subtitle={currentTask ? `Active context: ${currentTask.task_id.slice(0, 8)}… — ${currentTask.target.path}` : 'No active tasks'}
        actions={
          currentTask && (
            <Link
              to={`/tasks/${currentTask.task_id}`}
              className="text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150"
            >
              Open task →
            </Link>
          )
        }
      />

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : (
          <>
            {/* Agent Node Grid */}
            <div className="space-y-2">
              <h2 className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">Agent Nodes</h2>
              <div className="grid grid-cols-4 gap-2">
                {AGENT_NODES.map(agent => {
                  const status = getStatus(agent.id)
                  const routes = routeCounts[agent.id] ?? 0
                  const borderCls =
                    status === 'running'   ? 'border-[hsl(201_94%_40%/0.5)] ring-1 ring-[hsl(201_94%_40%/0.15)]' :
                    status === 'completed' ? 'border-[hsl(145_63%_40%/0.4)]' :
                                            'border-[hsl(var(--border))]'
                  return (
                    <div key={agent.id} className={`p-4 border rounded bg-[hsl(var(--card))] transition-all duration-200 ${borderCls}`}>
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <span className="text-sm font-semibold text-[hsl(var(--foreground))]">{agent.name}</span>
                        <AgentStatusDot status={status} />
                      </div>
                      <p className="text-[11px] text-[hsl(var(--muted-foreground))] leading-relaxed mb-3">{agent.desc}</p>
                      <div className="flex gap-4">
                        <div>
                          <div className="text-lg font-bold font-mono text-[hsl(var(--foreground))]">{routes}</div>
                          <div className="text-[9px] uppercase text-[hsl(var(--muted-foreground))] tracking-wider">routes</div>
                        </div>
                      </div>
                    </div>
                  )
                })}

                {/* Supervisor pseudo-node */}
                <div className="p-4 border border-dashed border-[hsl(var(--ring)/0.4)] rounded bg-[hsl(var(--ring)/0.04)]">
                  <div className="text-sm font-semibold text-[hsl(var(--ring))] mb-1">Supervisor</div>
                  <p className="text-[11px] text-[hsl(var(--muted-foreground))] leading-relaxed">Bounded routing engine — max steps, repeat limits, deterministic fallback.</p>
                </div>
              </div>
            </div>

            {/* Routing flow */}
            <div className="space-y-2">
              <h2 className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">Live Routing Events</h2>
              <div className="border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))] overflow-hidden">
                {trace.filter(e => e.event_type === 'AGENT_ROUTED').length === 0 ? (
                  <EmptyState
                    title="No routing events"
                    description={currentTask ? 'Run the task to see agent routing.' : 'Select or create a task first.'}
                  />
                ) : (
                  <div className="divide-y divide-[hsl(var(--border))]">
                    {trace.filter(e => e.event_type === 'AGENT_ROUTED').slice(-12).map((ev, i) => (
                      <div key={i} className="flex items-center gap-3 px-4 py-2.5 text-xs font-mono">
                        <span className="text-[hsl(var(--muted-foreground))] w-20 flex-shrink-0">{formatTime(ev.created_at)}</span>
                        <span className="text-[hsl(var(--muted-foreground))]">{ev.sender ?? '?'}</span>
                        <span className="text-[hsl(var(--ring))]">→</span>
                        <span className="text-[hsl(var(--foreground))]">{ev.receiver ?? '?'}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* All tasks status */}
            <div className="space-y-2">
              <h2 className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">Active Tasks</h2>
              <div className="border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))] overflow-hidden">
                {taskList.length === 0 ? (
                  <EmptyState title="No tasks" description="Create a task from the Tasks page." />
                ) : (
                  taskList.slice(0, 10).map(t => (
                    <div key={t.task_id} className="flex items-center gap-3 px-4 py-2.5 border-b border-[hsl(var(--border))] last:border-b-0 hover:bg-[hsl(var(--accent))] transition-colors duration-150">
                      <div className="flex-1 min-w-0 text-xs font-mono text-[hsl(var(--foreground))] truncate">{t.target.path}</div>
                      <TaskStatusBadge status={t.status} />
                      <Link to={`/tasks/${t.task_id}`} className="text-[10px] px-2 py-0.5 rounded border border-[hsl(var(--border))] hover:bg-[hsl(var(--accent))] transition-colors duration-150">
                        Open
                      </Link>
                    </div>
                  ))
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
