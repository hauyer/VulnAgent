import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAllFindings } from '@/hooks'
import { VulnStatusBadge } from '@/components/ui/StatusBadge'
import { Skeleton, EmptyState, ErrorState, IdCell } from '@/components/ui/Primitives'
import { Topbar } from '@/components/layout/Layout'
import { formatDateTime } from '@/lib/utils'
import type { VulnerabilityCandidate } from '@/types'

export default function FindingsPage() {
  const { data: findings = [], isLoading, error, refetch } = useAllFindings()
  const [statusFilter, setStatusFilter] = useState<string>('ALL')
  const [selected, setSelected] = useState<VulnerabilityCandidate | null>(null)

  const statuses = ['ALL', 'CANDIDATE', 'CONFIRMED', 'REJECTED', 'UNCERTAIN', 'VERIFYING']
  const filtered = statusFilter === 'ALL' ? findings : findings.filter(f => f.status === statusFilter)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Topbar
        title="Findings"
        subtitle={`${findings.length} vulnerability candidates across all tasks`}
        actions={
          <button onClick={() => refetch()} className="text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150" aria-label="Refresh findings">
            Refresh
          </button>
        }
      />

      {/* Status filter */}
      <div className="flex border-b border-[hsl(var(--border))] flex-shrink-0 bg-[hsl(var(--background))] overflow-x-auto">
        {statuses.map(s => {
          const count = s === 'ALL' ? findings.length : findings.filter(f => f.status === s).length
          return (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`flex items-center gap-1.5 px-4 py-2 text-xs font-medium border-b-2 transition-all duration-150 whitespace-nowrap ${
                statusFilter === s
                  ? 'border-[hsl(var(--ring))] text-[hsl(var(--foreground))]'
                  : 'border-transparent text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]'
              }`}
            >
              {s}
              <span className={`font-mono text-[10px] px-1 rounded border ${
                statusFilter === s
                  ? 'bg-[hsl(var(--ring)/0.15)] text-[hsl(var(--ring))] border-[hsl(var(--ring)/0.3)]'
                  : 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]'
              }`}>{count}</span>
            </button>
          )
        })}
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Table */}
        <div className="flex-1 overflow-auto">
          {isLoading ? (
            <div className="p-4 space-y-2">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-11 w-full" />)}</div>
          ) : error ? (
            <ErrorState message="Failed to load findings." onRetry={() => refetch()} />
          ) : filtered.length === 0 ? (
            <EmptyState
              icon={<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35M11 8v6M8 11h6"/></svg>}
              title="No findings"
              description="Vulnerability candidates appear here after analysis."
            />
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[hsl(var(--card))] border-b border-[hsl(var(--border))]">
                <tr>
                  {['Title','CWE','Type','Source','Status','Confidence','Task','Created'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 font-semibold text-[hsl(var(--muted-foreground))] uppercase tracking-wider text-[10px] whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[hsl(var(--border))]">
                {filtered.map(f => (
                  <tr
                    key={f.vulnerability_id}
                    onClick={() => setSelected(selected?.vulnerability_id === f.vulnerability_id ? null : f)}
                    className={`cursor-pointer transition-colors duration-150 ${
                      selected?.vulnerability_id === f.vulnerability_id
                        ? 'bg-[hsl(var(--accent))]'
                        : 'hover:bg-[hsl(var(--accent))]'
                    }`}
                  >
                    <td className="px-4 py-2.5 font-medium text-[hsl(var(--foreground))] max-w-[200px] truncate" title={f.title}>{f.title}</td>
                    <td className="px-4 py-2.5">
                      {f.cwe_id && (
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded border border-[hsl(0_72%_51%/0.3)] bg-[hsl(0_72%_51%/0.08)] text-[hsl(0_72%_51%)]">{f.cwe_id}</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[hsl(var(--muted-foreground))]">{f.vulnerability_type}</td>
                    <td className="px-4 py-2.5 font-mono text-[hsl(var(--muted-foreground))]">{f.source_agent}</td>
                    <td className="px-4 py-2.5"><VulnStatusBadge status={f.status} /></td>
                    <td className="px-4 py-2.5 font-mono text-[hsl(var(--muted-foreground))]">{Math.round(f.confidence * 100)}%</td>
                    <td className="px-4 py-2.5">
                      <Link
                        to={`/tasks/${f.task_id}`}
                        onClick={e => e.stopPropagation()}
                        className="font-mono text-[10px] text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors duration-150"
                      >
                        {f.task_id.slice(0, 8)}…
                      </Link>
                    </td>
                    <td className="px-4 py-2.5 text-[hsl(var(--muted-foreground))] font-mono whitespace-nowrap">{formatDateTime(f.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Detail drawer */}
        {selected && (
          <div className="w-72 flex-shrink-0 border-l border-[hsl(var(--border))] bg-[hsl(var(--card))] overflow-y-auto p-4 space-y-4">
            <div className="flex items-start justify-between gap-2">
              <div className="text-sm font-semibold text-[hsl(var(--foreground))] leading-tight">{selected.title}</div>
              <button onClick={() => setSelected(null)} className="text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] flex-shrink-0 transition-colors duration-150">✕</button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {selected.cwe_id && <span className="font-mono text-[10px] px-1.5 py-0.5 rounded border border-[hsl(0_72%_51%/0.3)] bg-[hsl(0_72%_51%/0.08)] text-[hsl(0_72%_51%)]">{selected.cwe_id}</span>}
              <VulnStatusBadge status={selected.status} />
            </div>
            {selected.description && <p className="text-xs text-[hsl(var(--muted-foreground))] leading-relaxed">{selected.description}</p>}
            <div className="space-y-1.5 text-[11px]">
              {[
                { k: 'Type',       v: selected.vulnerability_type },
                { k: 'Source',     v: selected.source_agent },
                { k: 'Confidence', v: `${Math.round(selected.confidence * 100)}%` },
                { k: 'Evidence',   v: `${selected.evidence_ids.length} items` },
              ].map(row => (
                <div key={row.k} className="flex gap-3">
                  <span className="font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))] w-20 flex-shrink-0 text-[10px]">{row.k}</span>
                  <span className="font-mono text-[hsl(var(--foreground))]">{row.v}</span>
                </div>
              ))}
            </div>
            {selected.location && (
              <div className="border border-[hsl(var(--border))] rounded bg-[hsl(var(--secondary))] p-2.5">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-1">Location</p>
                <pre className="text-[10px] font-mono text-[hsl(var(--foreground))] whitespace-pre-wrap break-all">{JSON.stringify(selected.location, null, 2)}</pre>
              </div>
            )}
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))] mb-1">Finding ID</p>
              <IdCell id={selected.vulnerability_id} />
            </div>
            <Link to={`/tasks/${selected.task_id}`} className="block text-center text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150">
              Open Task →
            </Link>
          </div>
        )}
      </div>
    </div>
  )
}
