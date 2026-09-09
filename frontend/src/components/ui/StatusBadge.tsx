import { cn } from '@/lib/utils'
import type { TaskStatus, VulnStatus } from '@/types'

// ── Status badge data ─────────────────────────────────────────────────────────
const TASK_STATUS_MAP: Record<
  string,
  { label: string; cls: string }
> = {
  created:         { label: 'Queued',    cls: 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]' },
  planning:        { label: 'Planning',  cls: 'bg-[hsl(213_94%_48%/0.1)] text-[hsl(213_94%_40%)] border-[hsl(213_94%_48%/0.25)]' },
  analyzing:       { label: 'Analyzing', cls: 'bg-[hsl(201_94%_44%/0.12)] text-[hsl(201_94%_36%)] border-[hsl(201_94%_44%/0.28)]' },
  dynamic_testing: { label: 'Fuzzing',   cls: 'bg-[hsl(201_94%_44%/0.12)] text-[hsl(201_94%_36%)] border-[hsl(201_94%_44%/0.28)]' },
  profiling:       { label: 'Profiling', cls: 'bg-[hsl(201_94%_44%/0.12)] text-[hsl(201_94%_36%)] border-[hsl(201_94%_44%/0.28)]' },
  verifying:       { label: 'Verifying', cls: 'bg-[hsl(38_92%_50%/0.12)] text-[hsl(38_92%_35%)] border-[hsl(38_92%_50%/0.28)]' },
  reporting:       { label: 'Reporting', cls: 'bg-[hsl(201_94%_44%/0.12)] text-[hsl(201_94%_36%)] border-[hsl(201_94%_44%/0.28)]' },
  completed:       { label: 'Completed', cls: 'bg-[hsl(145_60%_40%/0.12)] text-[hsl(145_60%_30%)] border-[hsl(145_60%_40%/0.28)]' },
  failed:          { label: 'Failed',    cls: 'bg-[hsl(0_72%_51%/0.1)] text-[hsl(0_72%_42%)] border-[hsl(0_72%_51%/0.25)]' },
}

const VULN_STATUS_MAP: Record<
  string,
  { label: string; cls: string }
> = {
  CANDIDATE:  { label: 'Candidate',  cls: 'bg-[hsl(213_85%_56%/0.12)] text-[hsl(213_85%_38%)] border-[hsl(213_85%_56%/0.28)]' },
  VERIFYING:  { label: 'Verifying',  cls: 'bg-[hsl(38_92%_50%/0.12)] text-[hsl(38_92%_35%)] border-[hsl(38_92%_50%/0.28)]' },
  CONFIRMED:  { label: 'Confirmed',  cls: 'bg-[hsl(0_72%_51%/0.1)] text-[hsl(0_72%_42%)] border-[hsl(0_72%_51%/0.28)]' },
  REJECTED:   { label: 'Rejected',   cls: 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]' },
  UNCERTAIN:  { label: 'Uncertain',  cls: 'bg-[hsl(38_92%_50%/0.12)] text-[hsl(38_92%_35%)] border-[hsl(38_92%_50%/0.28)]' },
}

const AGENT_STATUS_MAP: Record<string, { label: string; cls: string; dot: string }> = {
  pending:   { label: 'Pending',   cls: 'text-[hsl(var(--muted-foreground))]',  dot: 'bg-[hsl(var(--muted-foreground))]' },
  running:   { label: 'Running',   cls: 'text-[hsl(201_94%_40%)]',              dot: 'bg-[hsl(201_94%_40%)] animate-pulse' },
  completed: { label: 'Completed', cls: 'text-[hsl(145_63%_40%)]',              dot: 'bg-[hsl(145_63%_40%)]' },
  failed:    { label: 'Failed',    cls: 'text-[hsl(0_72%_51%)]',               dot: 'bg-[hsl(0_72%_51%)]' },
  skipped:   { label: 'Skipped',   cls: 'text-[hsl(var(--muted-foreground))]',  dot: 'bg-[hsl(var(--muted-foreground))]' },
}

const BASE_BADGE = 'inline-flex items-center gap-1 font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded border tracking-wide uppercase'

interface StatusBadgeProps {
  status: TaskStatus | string
  className?: string
}

export function TaskStatusBadge({ status, className }: StatusBadgeProps) {
  const s = (status ?? '').toLowerCase()
  const cfg = TASK_STATUS_MAP[s] ?? { label: s, cls: 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]' }
  const isLive = ['planning','analyzing','dynamic_testing','profiling','verifying','reporting'].includes(s)
  return (
    <span className={cn(BASE_BADGE, cfg.cls, className)}>
      {isLive && <span className="inline-block w-1.5 h-1.5 rounded-full bg-current animate-pulse" />}
      {cfg.label}
    </span>
  )
}

export function VulnStatusBadge({ status, className }: { status: VulnStatus | string; className?: string }) {
  const s = (status ?? '').toUpperCase()
  const cfg = VULN_STATUS_MAP[s] ?? VULN_STATUS_MAP['CANDIDATE']
  return (
    <span className={cn(BASE_BADGE, cfg.cls, className)}>
      {cfg.label}
    </span>
  )
}

export function AgentStatusDot({ status }: { status: string }) {
  const cfg = AGENT_STATUS_MAP[(status ?? '').toLowerCase()] ?? AGENT_STATUS_MAP['pending']
  return (
    <span className={cn('inline-flex items-center gap-1.5 text-xs font-medium', cfg.cls)}>
      <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', cfg.dot)} />
      {cfg.label}
    </span>
  )
}
