import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAllEvidence } from '@/hooks'
import { Skeleton, EmptyState, ErrorState, IdCell } from '@/components/ui/Primitives'
import { Topbar } from '@/components/layout/Layout'
import { formatDateTime } from '@/lib/utils'
import type { Evidence } from '@/types'

export default function EvidencePage() {
  const { data: evidence = [], isLoading, error, refetch } = useAllEvidence()
  const [typeFilter, setTypeFilter] = useState<string>('ALL')
  const [selected, setSelected] = useState<Evidence | null>(null)

  const types = ['ALL', ...Array.from(new Set(evidence.map(e => e.evidence_type))).sort()]
  const filtered = typeFilter === 'ALL' ? evidence : evidence.filter(e => e.evidence_type === typeFilter)

  const snippet = (ev: Evidence): string | null => {
    const p = ev.payload
    return (p.snippet ?? p.code ?? p.raw ?? null) as string | null
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Topbar
        title="Evidence"
        subtitle={`${evidence.length} evidence items — core of the Evidence-First principle`}
        actions={
          <button onClick={() => refetch()} className="text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150" aria-label="Refresh evidence">
            Refresh
          </button>
        }
      />

      {/* Type filter */}
      <div className="flex border-b border-[hsl(var(--border))] flex-shrink-0 bg-[hsl(var(--background))] overflow-x-auto">
        {types.map(t => {
          const count = t === 'ALL' ? evidence.length : evidence.filter(e => e.evidence_type === t).length
          return (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`flex items-center gap-1.5 px-3 py-2 text-[10px] font-medium border-b-2 transition-all duration-150 whitespace-nowrap ${
                typeFilter === t
                  ? 'border-[hsl(var(--ring))] text-[hsl(var(--foreground))]'
                  : 'border-transparent text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]'
              }`}
            >
              {t}
              <span className={`font-mono text-[9px] px-1 rounded border ${
                typeFilter === t
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
            <ErrorState message="Failed to load evidence." onRetry={() => refetch()} />
          ) : filtered.length === 0 ? (
            <EmptyState
              icon={<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>}
              title="No evidence"
              description="Evidence items are produced by analyzers, the fuzz engine, and the verification layer."
            />
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[hsl(var(--card))] border-b border-[hsl(var(--border))]">
                <tr>
                  {['Evidence ID','Type','Source Agent','Task','Summary','Created'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 font-semibold text-[hsl(var(--muted-foreground))] uppercase tracking-wider text-[10px] whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[hsl(var(--border))]">
                {filtered.map(ev => {
                  const s = snippet(ev)
                  return (
                    <tr
                      key={ev.evidence_id}
                      onClick={() => setSelected(selected?.evidence_id === ev.evidence_id ? null : ev)}
                      className={`cursor-pointer transition-colors duration-150 ${
                        selected?.evidence_id === ev.evidence_id ? 'bg-[hsl(var(--accent))]' : 'hover:bg-[hsl(var(--accent))]'
                      }`}
                    >
                      <td className="px-4 py-2.5"><IdCell id={ev.evidence_id} /></td>
                      <td className="px-4 py-2.5">
                        <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border border-[hsl(201_94%_40%/0.3)] bg-[hsl(201_94%_40%/0.08)] text-[hsl(201_94%_40%)] uppercase">
                          {ev.evidence_type}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[hsl(var(--muted-foreground))]">{ev.source_agent ?? '—'}</td>
                      <td className="px-4 py-2.5">
                        <Link
                          to={`/tasks/${ev.task_id}`}
                          onClick={e => e.stopPropagation()}
                          className="font-mono text-[10px] text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors duration-150"
                        >
                          {ev.task_id.slice(0, 8)}…
                        </Link>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[hsl(var(--muted-foreground))] max-w-[240px] truncate">
                        {s ? String(s).slice(0, 60) : '—'}
                      </td>
                      <td className="px-4 py-2.5 text-[hsl(var(--muted-foreground))] font-mono whitespace-nowrap">{formatDateTime(ev.created_at)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Detail drawer */}
        {selected && (
          <div className="w-72 flex-shrink-0 border-l border-[hsl(var(--border))] bg-[hsl(var(--card))] overflow-y-auto p-4 space-y-4">
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
                <pre className="text-[10px] font-mono text-[hsl(var(--foreground))] bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] rounded p-2.5 overflow-auto max-h-48 whitespace-pre-wrap break-all">
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
            <Link to={`/tasks/${selected.task_id}`} className="block text-center text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] hover:bg-[hsl(var(--accent))] transition-colors duration-150">
              Open Task →
            </Link>
          </div>
        )}
      </div>
    </div>
  )
}
