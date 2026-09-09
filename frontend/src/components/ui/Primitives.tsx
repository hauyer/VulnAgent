import { cn } from '@/lib/utils'

// ── Skeleton ──────────────────────────────────────────────────────────────────
export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'animate-pulse rounded bg-[hsl(var(--secondary))]',
        className
      )}
    />
  )
}

// ── Empty State ───────────────────────────────────────────────────────────────
interface EmptyStateProps {
  icon?: React.ReactNode
  title: string
  description?: string
  action?: React.ReactNode
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 px-6 text-center">
      {icon && (
        <div className="text-[hsl(var(--muted-foreground))] opacity-40">
          {icon}
        </div>
      )}
      <p className="text-sm font-semibold text-[hsl(var(--foreground))]">{title}</p>
      {description && (
        <p className="text-xs text-[hsl(var(--muted-foreground))] max-w-xs leading-relaxed">{description}</p>
      )}
      {action && <div className="mt-1">{action}</div>}
    </div>
  )
}

// ── Error State ───────────────────────────────────────────────────────────────
interface ErrorStateProps {
  title?: string
  message: string
  onRetry?: () => void
}

export function ErrorState({ title = 'Something went wrong', message, onRetry }: ErrorStateProps) {
  return (
    <div className="flex flex-col items-center gap-3 py-12 px-6 text-center">
      <div className="w-10 h-10 rounded-full bg-[hsl(0_72%_51%/0.1)] border border-[hsl(0_72%_51%/0.2)] flex items-center justify-center">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="hsl(0,72%,51%)" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      </div>
      <p className="text-sm font-semibold text-[hsl(var(--foreground))]">{title}</p>
      <p className="text-xs text-[hsl(var(--muted-foreground))] max-w-xs">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-1 text-xs px-3 py-1.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors duration-150"
        >
          Retry
        </button>
      )}
    </div>
  )
}

// ── ID Cell — truncated with copy on click ────────────────────────────────────
import { copyToClipboard, truncateId } from '@/lib/utils'
import { useState } from 'react'

export function IdCell({ id }: { id: string | null | undefined }) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    if (!id) return
    copyToClipboard(id)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <span
      title={id ?? '—'}
      onClick={handleCopy}
      className="font-mono text-xs text-[hsl(var(--muted-foreground))] cursor-pointer hover:text-[hsl(var(--foreground))] transition-colors duration-150"
    >
      {copied ? '✓ copied' : truncateId(id)}
    </span>
  )
}
