import { NavLink, Link } from 'react-router-dom'
import { useHealth } from '@/hooks'
import { cn } from '@/lib/utils'

const NAV = [
  { to: '/',          label: 'Dashboard',  icon: LayoutDashboardIcon },
  { to: '/tasks',     label: 'Tasks',      icon: ListIcon },
  { to: '/runtime',   label: 'Runtime',    icon: CpuIcon },
  { to: '/findings',  label: 'Findings',   icon: SearchIcon },
  { to: '/evidence',  label: 'Evidence',   icon: FileTextIcon },
  { to: '/reports',   label: 'Reports',    icon: ClipboardIcon },
]

function LayoutDashboardIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>
      <rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>
    </svg>
  )
}
function ListIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/>
      <line x1="8" y1="18" x2="21" y2="18"/>
      <circle cx="3" cy="6" r="1.5" fill="currentColor" stroke="none"/>
      <circle cx="3" cy="12" r="1.5" fill="currentColor" stroke="none"/>
      <circle cx="3" cy="18" r="1.5" fill="currentColor" stroke="none"/>
    </svg>
  )
}
function CpuIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <rect x="4" y="4" width="16" height="16" rx="2"/>
      <rect x="9" y="9" width="6" height="6"/>
      <line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/>
      <line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/>
      <line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="15" x2="23" y2="15"/>
      <line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="15" x2="4" y2="15"/>
    </svg>
  )
}
function SearchIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
    </svg>
  )
}
function FileTextIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
      <polyline points="10 9 9 9 8 9"/>
    </svg>
  )
}
function ClipboardIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>
      <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
    </svg>
  )
}

export function Sidebar() {
  const { data: health } = useHealth()
  const isOnline = health?.status === 'ok'

  return (
    <aside className="flex flex-col w-[220px] border-r border-[hsl(var(--border))] bg-[hsl(212_45%_97%)] h-full overflow-hidden flex-shrink-0">
      {/* Brand */}
      <Link
        to="/"
        className="flex items-center gap-2.5 h-[52px] px-4 border-b border-[hsl(var(--border))] flex-shrink-0 bg-[hsl(var(--card))]"
      >
        <span className="w-7 h-7 rounded border border-[hsl(213_94%_48%/0.25)] bg-[hsl(213_94%_48%/0.1)] flex items-center justify-center text-[hsl(213_94%_48%)] flex-shrink-0 shadow-xs">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </span>
        <div className="flex flex-col min-w-0">
          <span className="text-sm font-semibold text-[hsl(var(--foreground))] leading-none">VulnAgent</span>
          <span className="text-[10px] font-mono text-[hsl(213_94%_48%)] font-medium mt-0.5">V0.2 Platform</span>
        </div>
      </Link>

      {/* Nav */}
      <nav className="flex-1 py-3 px-2 overflow-y-auto space-y-1">
        {NAV.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-all duration-150 outline-none',
                isActive
                  ? 'bg-[hsl(213_94%_48%/0.12)] text-[hsl(213_94%_48%)] font-semibold border border-[hsl(213_94%_48%/0.25)] shadow-xs'
                  : 'text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] hover:bg-[hsl(214_70%_93%/0.6)]',
              )
            }
          >
            <Icon />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Health footer */}
      <div className="flex-shrink-0 border-t border-[hsl(var(--border))] px-4 py-2.5 flex items-center gap-2 bg-[hsl(var(--card))]">
        <span
          className={cn(
            'w-2 h-2 rounded-full flex-shrink-0',
            isOnline ? 'bg-[hsl(145_63%_40%)] shadow-xs' : 'bg-[hsl(var(--muted-foreground))]'
          )}
        />
        <span className="text-[11px] text-[hsl(var(--muted-foreground))] font-mono truncate">
          {isOnline ? `API online · ${health?.service ?? 'vulnagent'}` : 'API offline'}
        </span>
      </div>
    </aside>
  )
}

export function Topbar({ title, subtitle, actions }: {
  title: React.ReactNode
  subtitle?: React.ReactNode
  actions?: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4 px-5 h-[52px] border-b border-[hsl(var(--border))] bg-[hsl(var(--card))] flex-shrink-0">
      <div className="flex flex-col min-w-0">
        <div className="text-sm font-semibold text-[hsl(var(--foreground))] leading-tight truncate">{title}</div>
        {subtitle && <div className="text-[11px] text-[hsl(var(--muted-foreground))] font-mono mt-0.5 truncate">{subtitle}</div>}
      </div>
      {actions && <div className="flex items-center gap-2 flex-shrink-0">{actions}</div>}
    </div>
  )
}
