import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  useTask,
  useRunTask,
  useTaskFindings,
  useTaskEvidence,
  useTaskTrace,
  useTaskVerifications,
  useTaskReport,
} from '@/hooks'
import { TaskStatusBadge, VulnStatusBadge } from '@/components/ui/StatusBadge'
import { Skeleton, EmptyState, ErrorState, IdCell } from '@/components/ui/Primitives'
import { Topbar } from '@/components/layout/Layout'
import { formatDateTime, formatDuration, formatTime } from '@/lib/utils'
import type { TraceEvent, VulnerabilityCandidate, Evidence, VerificationResult, Report } from '@/types'

type TabKey = 'overview' | 'runtime' | 'findings' | 'evidence' | 'trace' | 'report'

const TABS: { key: TabKey; label: string }[] = [
  { key: 'overview',     label: 'Overview' },
  { key: 'runtime',      label: 'Runtime' },
  { key: 'findings',     label: 'Findings' },
  { key: 'evidence',     label: 'Evidence' },
  { key: 'trace',        label: 'Trace' },
  { key: 'report',       label: 'Report' },
]

const RUNNING = new Set(['planning','analyzing','dynamic_testing','profiling','verifying','reporting'])

// ── Overview tab ──────────────────────────────────────────────────────────────
function OverviewTab({ taskId, status }: { taskId: string; status: string }) {
  const { data: task } = useTask(taskId)
  const { data: trace = [] } = useTaskTrace(taskId, status)
  const { data: findings = [] } = useTaskFindings(taskId, status)

  // Derive agent progress from trace events
  const agentsDone = new Set<string>()
  const agentsRunning = new Set<string>()
  for (const ev of trace) {
    if (ev.event_type === 'AGENT_COMPLETED') agentsDone.add(ev.sender ?? '')
    if (ev.event_type === 'AGENT_STARTED')   agentsRunning.add(ev.sender ?? '')
  }
  const agentOrder = ['planner','source_audit','binary_analysis','fuzz_agent','verification_agent','reviewer_agent','report_agent']

  return (
    <div className="space-y-5">
      {/* Basic info */}
      <div className="border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))] divide-y divide-[hsl(var(--border))]">
        {[
          { k: 'Task ID',     v: task?.task_id },
          { k: 'Target',      v: task?.target?.path },
          { k: 'Type',        v: task?.target?.target_type?.toUpperCase() },
          { k: 'Created At',  v: formatDateTime(task?.created_at) },
          { k: 'Duration',    v: formatDuration(task?.created_at, task?.completed_at) },
          { k: 'Findings',    v: findings.length },
          { k: 'Error',       v: task?.error_message ?? '—' },
        ].map(row => (
          <div key={row.k} className="flex items-center px-4 py-2.5 gap-8">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))] w-28 flex-shrink-0">{row.k}</span>
            <span className="text-xs font-mono text-[hsl(var(--foreground))]">{row.v ?? '—'}</span>
          </div>
        ))}
      </div>

      {/* Analysis Progress — driven by real trace, not hardcoded */}
      <div className="space-y-2">
        <h3 className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">Analysis Progress</h3>
        <div className="border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))] divide-y divide-[hsl(var(--border))]">
          {agentOrder.map(agent => {
            const done    = agentsDone.has(agent)
            const running = agentsRunning.has(agent) && !done
            let dotCls = 'bg-[hsl(var(--muted-foreground))] opacity-30'
            let label = 'Pending'
            if (running) { dotCls = 'bg-[hsl(201_94%_40%)] animate-pulse'; label = 'Running' }
            if (done)    { dotCls = 'bg-[hsl(145_63%_40%)]'; label = 'Completed' }
            return (
              <div key={agent} className="flex items-center gap-3 px-4 py-2.5">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${dotCls}`} />
                <span className="text-xs font-mono text-[hsl(var(--foreground))]">{agent}</span>
                <span className="text-[10px] text-[hsl(var(--muted-foreground))] ml-auto">{label}</span>
              </div>
            )
          })}
          {trace.length === 0 && (
            <div className="px-4 py-3 text-[11px] text-[hsl(var(--muted-foreground))] italic">
              Progress tracked from Trace events — run the task to see agent routing.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Runtime tab ───────────────────────────────────────────────────────────────
const AGENT_NODES = [
  { id: 'planner',            name: 'Planner',          desc: 'Task planning & routing decisions' },
  { id: 'source_audit',       name: 'Source Audit',     desc: 'AST / CFG / taint / static rules' },
  { id: 'binary_analysis',    name: 'Binary Analysis',  desc: 'PE/ELF parsing, disassembly, CFG' },
  { id: 'fuzz_agent',         name: 'Fuzz',             desc: 'Seed corpus, mutation, crash analysis' },
  { id: 'verification_agent', name: 'Verification',     desc: 'Independent deduplication & verdict' },
  { id: 'reviewer_agent',     name: 'Reviewer',         desc: 'Second review for high-risk / conflicts' },
  { id: 'report_agent',       name: 'Report',           desc: 'Evidence chain & final report generation' },
]

function RuntimeTab({ taskId, taskStatus }: { taskId: string; taskStatus: string }) {
  const { data: trace = [] } = useTaskTrace(taskId, taskStatus)
  const { data: findings = [] } = useTaskFindings(taskId, taskStatus)
  const { data: evidence = [] } = useTaskEvidence(taskId, taskStatus)

  const agentsDone    = new Set(trace.filter(e => e.event_type === 'AGENT_COMPLETED').map(e => e.sender ?? ''))
  const agentsRunning = new Set(trace.filter(e => e.event_type === 'AGENT_STARTED').map(e => e.sender ?? ''))
  const routeCounts   = trace.filter(e => e.event_type === 'AGENT_ROUTED').reduce<Record<string, number>>((acc, e) => {
    const k = e.receiver ?? 'unknown'
    acc[k] = (acc[k] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="space-y-5">
      {/* Agent nodes grid */}
      <div className="grid grid-cols-4 gap-2">
        {AGENT_NODES.map(agent => {
          const done    = agentsDone.has(agent.id)
          const running = agentsRunning.has(agent.id) && !done
          const routes  = routeCounts[agent.id] ?? 0
          const evCount = evidence.filter(() => true).length   // placeholder — evidence has no agent grouping in current contract
          const findCount = findings.filter(f => f.source_agent === agent.id).length

          let borderCls = 'border-[hsl(var(--border))]'
          let headerCls = 'text-[hsl(var(--muted-foreground))]'
          if (running) { borderCls = 'border-[hsl(201_94%_40%/0.4)] ring-1 ring-[hsl(201_94%_40%/0.2)]'; headerCls = 'text-[hsl(201_94%_40%)]' }
          if (done)    { borderCls = 'border-[hsl(145_63%_40%/0.4)]'; headerCls = 'text-[hsl(145_63%_40%)]' }

          return (
            <div key={agent.id} className={`p-3 border rounded bg-[hsl(var(--card))] ${borderCls} transition-all duration-150`}>
              <div className="flex items-center gap-2 mb-2">
                <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                  running ? 'bg-[hsl(201_94%_40%)] animate-pulse' :
                  done    ? 'bg-[hsl(145_63%_40%)]' :
                            'bg-[hsl(var(--muted-foreground))] opacity-30'
                }`} />
                <span className={`text-xs font-semibold ${headerCls}`}>{agent.name}</span>
              </div>
              <p className="text-[10px] text-[hsl(var(--muted-foreground))] leading-relaxed mb-2">{agent.desc}</p>
              <div className="grid grid-cols-3 gap-1">
                <div className="text-center">
                  <div className="font-mono text-sm font-bold text-[hsl(var(--foreground))]">{routes}</div>
                  <div className="text-[9px] text-[hsl(var(--muted-foreground))] uppercase">routes</div>
                </div>
                <div className="text-center">
                  <div className="font-mono text-sm font-bold text-[hsl(var(--foreground))]">{findCount}</div>
                  <div className="text-[9px] text-[hsl(var(--muted-foreground))] uppercase">findings</div>
                </div>
                <div className="text-center">
                  <div className="font-mono text-sm font-bold text-[hsl(var(--foreground))]">{evCount}</div>
                  <div className="text-[9px] text-[hsl(var(--muted-foreground))] uppercase">evidence</div>
                </div>
              </div>
            </div>
          )
        })}
        <div className="p-3 border border-dashed border-[hsl(var(--border))] rounded opacity-40 flex items-center justify-center">
          <span className="text-[10px] text-[hsl(var(--muted-foreground))] text-center">Supervisor<br/>Router</span>
        </div>
      </div>

      {/* Route flow legend */}
      <div className="border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))] p-4 space-y-2">
        <h3 className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">Routing Events</h3>
        {trace.filter(e => e.event_type === 'AGENT_ROUTED').length === 0 ? (
          <p className="text-[11px] text-[hsl(var(--muted-foreground))] italic">No routing events yet.</p>
        ) : (
          <div className="space-y-1">
            {trace.filter(e => e.event_type === 'AGENT_ROUTED').map((ev, i) => (
              <div key={i} className="flex items-center gap-2 text-[11px] font-mono text-[hsl(var(--foreground))]">
                <span className="text-[hsl(var(--muted-foreground))]">{formatTime(ev.created_at)}</span>
                <span className="text-[hsl(var(--muted-foreground))]">{ev.sender ?? '?'}</span>
                <span className="text-[hsl(var(--ring))]">→</span>
                <span>{ev.receiver ?? '?'}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Findings tab ──────────────────────────────────────────────────────────────
function FindingsTab({ taskId, taskStatus }: { taskId: string; taskStatus: string }) {
  const { data: findings = [], isLoading, error, refetch } = useTaskFindings(taskId, taskStatus)
  const [selected, setSelected] = useState<VulnerabilityCandidate | null>(null)

  if (isLoading) return <div className="space-y-2">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}</div>
  if (error) return <ErrorState message="Failed to load findings." onRetry={() => refetch()} />
  if (findings.length === 0) return (
    <EmptyState
      icon={<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35M11 8v6M8 11h6"/></svg>}
      title="No findings"
      description="Vulnerability candidates will appear here after analysis runs."
    />
  )

  return (
    <div className="flex gap-4">
      <div className="flex-1 min-w-0 space-y-2">
        {findings.map(f => (
          <div
            key={f.vulnerability_id}
            onClick={() => setSelected(selected?.vulnerability_id === f.vulnerability_id ? null : f)}
            className={`p-4 border rounded bg-[hsl(var(--card))] cursor-pointer transition-all duration-150 ${
              selected?.vulnerability_id === f.vulnerability_id
                ? 'border-[hsl(var(--ring)/0.5)] ring-1 ring-[hsl(var(--ring)/0.2)]'
                : 'border-[hsl(var(--border))] hover:border-[hsl(var(--ring)/0.3)]'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-[hsl(var(--foreground))]">{f.title}</div>
                <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                  {f.cwe_id && (
                    <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border border-[hsl(0_72%_51%/0.3)] bg-[hsl(0_72%_51%/0.08)] text-[hsl(0_72%_51%)]">
                      {f.cwe_id}
                    </span>
                  )}
                  <VulnStatusBadge status={f.status} />
                  <span className="text-[10px] font-mono text-[hsl(var(--muted-foreground))]">{f.vulnerability_type}</span>
                </div>
              </div>
              <div className="flex flex-col items-end gap-1 flex-shrink-0">
                <div className="flex items-center gap-2">
                  <div className="w-16 h-1 rounded bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] overflow-hidden">
                    <div className="h-full bg-[hsl(var(--ring))] rounded" style={{ width: `${Math.round(f.confidence * 100)}%` }} />
                  </div>
                  <span className="text-[10px] font-mono text-[hsl(var(--muted-foreground))]">{Math.round(f.confidence * 100)}%</span>
                </div>
                <span className="text-[10px] font-mono text-[hsl(var(--muted-foreground))]">{f.source_agent}</span>
              </div>
            </div>
            {f.description && (
              <p className="text-xs text-[hsl(var(--muted-foreground))] mt-2 line-clamp-2 leading-relaxed">{f.description}</p>
            )}
          </div>
        ))}
      </div>

      {/* Detail drawer */}
      {selected && (
        <div className="w-72 flex-shrink-0 border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))] overflow-y-auto max-h-[70vh] p-4 space-y-4">
          <div className="flex items-start justify-between gap-2">
            <div className="text-sm font-semibold text-[hsl(var(--foreground))] leading-tight">{selected.title}</div>
            <button onClick={() => setSelected(null)} className="text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] flex-shrink-0 transition-colors duration-150">✕</button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {selected.cwe_id && <span className="font-mono text-[10px] px-1.5 py-0.5 rounded border border-[hsl(0_72%_51%/0.3)] bg-[hsl(0_72%_51%/0.08)] text-[hsl(0_72%_51%)]">{selected.cwe_id}</span>}
            <VulnStatusBadge status={selected.status} />
          </div>
          {selected.description && <p className="text-xs text-[hsl(var(--muted-foreground))] leading-relaxed">{selected.description}</p>}
          <div className="space-y-1.5">
            {[
              { k: 'Type',       v: selected.vulnerability_type },
              { k: 'Source',     v: selected.source_agent },
              { k: 'Confidence', v: `${Math.round(selected.confidence * 100)}%` },
              { k: 'Evidence',   v: `${selected.evidence_ids.length} items` },
            ].map(row => (
              <div key={row.k} className="flex gap-3">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))] w-20 flex-shrink-0">{row.k}</span>
                <span className="text-[11px] font-mono text-[hsl(var(--foreground))]">{row.v}</span>
              </div>
            ))}
          </div>
          {selected.location && (
            <div className="border border-[hsl(var(--border))] rounded bg-[hsl(var(--secondary))] p-2.5">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-1">Location</p>
              <pre className="text-[10px] font-mono text-[hsl(var(--foreground))] whitespace-pre-wrap break-all">
                {JSON.stringify(selected.location, null, 2)}
              </pre>
            </div>
          )}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-1">Finding ID</p>
            <IdCell id={selected.vulnerability_id} />
          </div>
        </div>
      )}
    </div>
  )
}

// ── Evidence tab ──────────────────────────────────────────────────────────────
function EvidenceTab({ taskId, taskStatus }: { taskId: string; taskStatus: string }) {
  const { data: evidence = [], isLoading, error, refetch } = useTaskEvidence(taskId, taskStatus)
  const [selected, setSelected] = useState<Evidence | null>(null)

  if (isLoading) return <div className="space-y-2">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-14 w-full" />)}</div>
  if (error) return <ErrorState message="Failed to load evidence." onRetry={() => refetch()} />
  if (evidence.length === 0) return (
    <EmptyState
      icon={<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>}
      title="No evidence"
      description="Evidence items are attached by analyzers and the fuzz engine."
    />
  )

  const snippet = (ev: Evidence) => {
    const p = ev.payload
    return (p.snippet ?? p.code ?? p.raw ?? null) as string | null
  }

  return (
    <div className="flex gap-4">
      <div className="flex-1 min-w-0 space-y-2">
        {evidence.map(ev => (
          <div
            key={ev.evidence_id}
            onClick={() => setSelected(selected?.evidence_id === ev.evidence_id ? null : ev)}
            className={`p-3 border rounded bg-[hsl(var(--card))] cursor-pointer transition-all duration-150 ${
              selected?.evidence_id === ev.evidence_id
                ? 'border-[hsl(var(--ring)/0.5)]'
                : 'border-[hsl(var(--border))] hover:border-[hsl(var(--ring)/0.3)]'
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border border-[hsl(201_94%_40%/0.3)] bg-[hsl(201_94%_40%/0.08)] text-[hsl(201_94%_40%)] uppercase">
                {ev.evidence_type}
              </span>
              <span className="text-[11px] text-[hsl(var(--muted-foreground))] font-mono">{ev.source_agent ?? '—'}</span>
              <span className="text-[11px] text-[hsl(var(--muted-foreground))] ml-auto font-mono">{formatTime(ev.created_at)}</span>
            </div>
            {snippet(ev) && (
              <pre className="mt-2 text-[10px] font-mono text-[hsl(var(--muted-foreground))] bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] rounded p-2 overflow-x-auto whitespace-pre-wrap break-all line-clamp-3">
                {String(snippet(ev)).slice(0, 120)}
              </pre>
            )}
          </div>
        ))}
      </div>

      {selected && (
        <div className="w-72 flex-shrink-0 border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))] overflow-y-auto max-h-[70vh] p-4 space-y-4">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border border-[hsl(201_94%_40%/0.3)] bg-[hsl(201_94%_40%/0.08)] text-[hsl(201_94%_40%)] uppercase">{selected.evidence_type}</span>
            <button onClick={() => setSelected(null)} className="text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors duration-150">✕</button>
          </div>
          <div className="space-y-1.5">
            {[
              { k: 'Source', v: selected.source_agent ?? '—' },
              { k: 'Created', v: formatDateTime(selected.created_at) },
            ].map(row => (
              <div key={row.k} className="flex gap-3">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))] w-16 flex-shrink-0">{row.k}</span>
                <span className="text-[11px] font-mono text-[hsl(var(--foreground))]">{row.v}</span>
              </div>
            ))}
          </div>
          {snippet(selected) && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-1">Content</p>
              <pre className="text-[10px] font-mono text-[hsl(var(--foreground))] bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] rounded p-2.5 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                {String(snippet(selected))}
              </pre>
            </div>
          )}
          <details>
            <summary className="text-[11px] text-[hsl(var(--muted-foreground))] cursor-pointer hover:text-[hsl(var(--foreground))] transition-colors duration-150">Raw payload</summary>
            <pre className="mt-2 text-[10px] font-mono text-[hsl(var(--muted-foreground))] bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] rounded p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
              {JSON.stringify(selected.payload, null, 2)}
            </pre>
          </details>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-1">Evidence ID</p>
            <IdCell id={selected.evidence_id} />
          </div>
        </div>
      )}
    </div>
  )
}

// ── Trace tab ─────────────────────────────────────────────────────────────────
function TraceTab({ taskId, taskStatus }: { taskId: string; taskStatus: string }) {
  const { data: trace = [], isLoading, error, refetch } = useTaskTrace(taskId, taskStatus)

  if (isLoading) return <div className="space-y-2">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
  if (error) return <ErrorState message="Failed to load trace." onRetry={() => refetch()} />
  if (trace.length === 0) return (
    <EmptyState
      icon={<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 20V10M18 20V4M6 20v-4"/></svg>}
      title="No trace events"
      description="Agent routing events will appear here once the task runs."
    />
  )

  return (
    <div className="space-y-0 relative">
      {trace.map((ev: TraceEvent, i: number) => {
        const isLast = i === trace.length - 1
        return (
          <div key={i} className="flex gap-3 pb-4">
            <div className="flex flex-col items-center w-5 flex-shrink-0">
              <span className={`w-2 h-2 rounded-full border flex-shrink-0 mt-0.5 ${
                isLast ? 'border-[hsl(var(--ring))] bg-[hsl(var(--ring))]' : 'border-[hsl(var(--border))] bg-[hsl(var(--background))]'
              }`} />
              {!isLast && <span className="flex-1 w-px bg-[hsl(var(--border))] mt-1" />}
            </div>
            <div className="flex-1 min-w-0 pb-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-semibold font-mono text-[hsl(var(--foreground))]">{ev.event_type}</span>
                {ev.sender && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))]">
                    {ev.sender}
                  </span>
                )}
                {ev.receiver && (
                  <>
                    <span className="text-[hsl(var(--ring))] text-xs">→</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-[hsl(var(--ring)/0.3)] bg-[hsl(var(--ring)/0.08)] text-[hsl(var(--ring))]">
                      {ev.receiver}
                    </span>
                  </>
                )}
                <span className="text-[10px] font-mono text-[hsl(var(--muted-foreground))] ml-auto">{formatTime(ev.created_at)}</span>
              </div>
              {ev.payload && Object.keys(ev.payload).length > 0 && (
                <details className="mt-1">
                  <summary className="text-[10px] text-[hsl(var(--muted-foreground))] cursor-pointer hover:text-[hsl(var(--foreground))] transition-colors duration-150">payload</summary>
                  <pre className="mt-1 text-[10px] font-mono text-[hsl(var(--muted-foreground))] bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] rounded p-2 overflow-auto max-h-28 whitespace-pre-wrap break-all">
                    {JSON.stringify(ev.payload, null, 2)}
                  </pre>
                </details>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Verification tab ──────────────────────────────────────────────────────────
function VerificationTab({ taskId, taskStatus }: { taskId: string; taskStatus: string }) {
  const { data: verifs = [], isLoading, error, refetch } = useTaskVerifications(taskId, taskStatus)

  if (isLoading) return <div className="space-y-2">{[...Array(2)].map((_, i) => <Skeleton key={i} className="h-20 w-full" />)}</div>
  if (error) return <ErrorState message="Failed to load verifications." onRetry={() => refetch()} />
  if (verifs.length === 0) return (
    <EmptyState
      icon={<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>}
      title="No verifications"
      description="Only the Verification layer produces CONFIRMED / REJECTED / UNCERTAIN verdicts."
    />
  )

  return (
    <div className="space-y-3">
      {verifs.map((v: VerificationResult) => (
        <div key={v.verification_id} className="border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))] overflow-hidden">
          <div className="flex items-center gap-3 px-4 py-3 bg-[hsl(var(--secondary))] border-b border-[hsl(var(--border))]">
            <VulnStatusBadge status={v.status} />
            <div className="flex-1 min-w-0">
              <IdCell id={v.vulnerability_id} />
            </div>
            <span className="text-[11px] font-mono text-[hsl(var(--muted-foreground))]">
              Confidence: {Math.round(v.confidence * 100)}%
            </span>
          </div>
          <div className="px-4 py-3 space-y-2">
            {v.rationale && <p className="text-xs text-[hsl(var(--muted-foreground))] leading-relaxed">{v.rationale}</p>}
            <p className="text-[10px] font-mono text-[hsl(var(--muted-foreground))]">
              Evidence: {v.evidence_ids.join(', ') || 'none'}
            </p>
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Report tab ─────────────────────────────────────────────────────────────────
function ReportTab({ taskId }: { taskId: string }) {
  const { data: report, isLoading, error, refetch } = useTaskReport(taskId)

  if (isLoading) return <div className="space-y-3"><Skeleton className="h-24 w-full" /><Skeleton className="h-40 w-full" /></div>
  if (error) return (
    <EmptyState
      icon={<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>}
      title="Report not ready"
      description="The report is generated after the task reaches COMPLETED status."
    />
  )
  if (!report) return null

  const summary = report.summary ?? {}
  const vulns   = report.vulnerabilities ?? []

  function downloadJson() {
    const b = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(b)
    a.download = `vulnagent-report-${taskId.slice(0, 8)}.json`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 pb-4 border-b border-[hsl(var(--border))]">
        <div>
          <h2 className="text-lg font-bold text-[hsl(var(--foreground))] leading-tight">{report.title ?? 'Security Audit Report'}</h2>
          <p className="text-[11px] font-mono text-[hsl(var(--muted-foreground))] mt-1">{formatDateTime(report.created_at)}</p>
        </div>
        <div className="flex gap-1.5 flex-shrink-0">
          <button onClick={downloadJson} className="text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150">
            Export JSON
          </button>
          <button onClick={() => window.print()} className="text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150">
            Print
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-0 border border-[hsl(var(--border))] rounded overflow-hidden bg-[hsl(var(--card))]">
        <div className="p-3 border-r border-[hsl(var(--border))]">
          <div className="text-[10px] text-[hsl(var(--muted-foreground))] uppercase tracking-wider font-semibold">Candidates</div>
          <div className="text-2xl font-bold font-mono text-[hsl(var(--foreground))] mt-1">{summary.total_candidates ?? vulns.length}</div>
        </div>
        <div className="p-3 border-r border-[hsl(var(--border))]">
          <div className="text-[10px] text-[hsl(var(--muted-foreground))] uppercase tracking-wider font-semibold">Confirmed</div>
          <div className="text-2xl font-bold font-mono text-[hsl(0_72%_51%)] mt-1">{summary.confirmed ?? '—'}</div>
        </div>
        <div className="p-3">
          <div className="text-[10px] text-[hsl(var(--muted-foreground))] uppercase tracking-wider font-semibold">Rejected</div>
          <div className="text-2xl font-bold font-mono text-[hsl(var(--foreground))] mt-1">{summary.rejected ?? '—'}</div>
        </div>
      </div>

      {/* Executive Summary */}
      {summary.executive_summary && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-[hsl(var(--foreground))] border-b border-[hsl(var(--border))] pb-1.5">Executive Summary</h3>
          <p className="text-sm text-[hsl(var(--muted-foreground))] leading-relaxed">{summary.executive_summary}</p>
        </div>
      )}

      {/* Vulnerability list */}
      {vulns.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-[hsl(var(--foreground))] border-b border-[hsl(var(--border))] pb-1.5">Vulnerabilities ({vulns.length})</h3>
          <div className="space-y-2">
            {vulns.map(v => (
              <div key={v.vulnerability_id} className="p-3 border border-[hsl(var(--border))] rounded bg-[hsl(var(--card))]">
                <div className="flex items-start gap-2">
                  <VulnStatusBadge status={v.status} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-[hsl(var(--foreground))]">{v.title}</div>
                    {v.description && <p className="text-[11px] text-[hsl(var(--muted-foreground))] mt-1 leading-relaxed">{v.description}</p>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main Task Detail Page ─────────────────────────────────────────────────────
export default function TaskDetailPage() {
  const { taskId } = useParams<{ taskId: string }>()
  const [activeTab, setActiveTab] = useState<TabKey>('overview')
  const runTask = useRunTask()

  const { data: task, isLoading, error } = useTask(taskId)
  const {
    data: findings = [],
    isLoading: findingsLoading,
  } = useTaskFindings(taskId, task?.status)
  const { data: evidence = [] } = useTaskEvidence(taskId, task?.status)
  const { data: trace = [] } = useTaskTrace(taskId, task?.status)
  const { data: verifs = [] } = useTaskVerifications(taskId, task?.status)

  if (!taskId) return null

  if (isLoading) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        <div className="h-[52px] border-b border-[hsl(var(--border))] bg-[hsl(var(--card))] flex items-center px-5 gap-3">
          <Skeleton className="h-4 w-48" />
        </div>
        <div className="flex-1 p-5 space-y-3">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
        </div>
      </div>
    )
  }

  if (error || !task) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        <Topbar title="Task not found" />
        <ErrorState title="Task not found" message={`No task with ID ${taskId}`} />
      </div>
    )
  }

  const isRunning = RUNNING.has(task.status)

  const tabCounts: Partial<Record<TabKey, number>> = {
    findings:     findings.length,
    evidence:     evidence.length,
    trace:        trace.length,
    report:       0,
    runtime:      0,
    overview:     0,
  }

  async function handleRun() {
    if (!taskId) return
    await runTask.mutateAsync(taskId)
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Topbar
        title={
          <span className="flex items-center gap-2">
            <Link to="/tasks" className="text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors duration-150">Tasks</Link>
            <span className="text-[hsl(var(--muted-foreground))]">/</span>
            <span>{task.target.path}</span>
            <TaskStatusBadge status={task.status} />
          </span>
        }
        subtitle={`${task.task_id} · ${task.target.target_type.toUpperCase()} · ${formatDateTime(task.created_at)}`}
        actions={
          <div className="flex gap-1.5 items-center">
            <button
              onClick={handleRun}
              disabled={isRunning || task.status === 'completed' || runTask.isPending}
              className="flex items-center gap-1.5 h-7 px-3 text-xs rounded bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] disabled:opacity-40 disabled:cursor-not-allowed hover:opacity-90 transition-all duration-150 font-medium"
              aria-label="Run task"
            >
              {isRunning ? <span className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin" /> : (
                <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
              )}
              {isRunning ? 'Running…' : 'Run'}
            </button>
          </div>
        }
      />

      {/* Tab bar */}
      <div className="flex border-b border-[hsl(var(--border))] flex-shrink-0 bg-[hsl(var(--background))] overflow-x-auto">
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 transition-all duration-150 whitespace-nowrap ${
              activeTab === t.key
                ? 'border-[hsl(var(--ring))] text-[hsl(var(--foreground))]'
                : 'border-transparent text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]'
            }`}
          >
            {t.label}
            {(tabCounts[t.key] ?? 0) > 0 && (
              <span className={`font-mono text-[10px] px-1 rounded border ${
                activeTab === t.key
                  ? 'bg-[hsl(var(--ring)/0.15)] text-[hsl(var(--ring))] border-[hsl(var(--ring)/0.3)]'
                  : 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]'
              }`}>
                {tabCounts[t.key]}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto p-5">
        {activeTab === 'overview'     && <OverviewTab taskId={taskId} status={task.status} />}
        {activeTab === 'runtime'      && <RuntimeTab taskId={taskId} taskStatus={task.status} />}
        {activeTab === 'findings'     && <FindingsTab taskId={taskId} taskStatus={task.status} />}
        {activeTab === 'evidence'     && <EvidenceTab taskId={taskId} taskStatus={task.status} />}
        {activeTab === 'trace'        && <TraceTab taskId={taskId} taskStatus={task.status} />}
        {activeTab === 'report'       && <ReportTab taskId={taskId} />}
      </div>
    </div>
  )
}
