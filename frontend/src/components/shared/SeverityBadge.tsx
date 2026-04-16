import { clsx } from 'clsx'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

interface SeverityBadgeProps {
  severity: string
}

const severityConfig: Record<Severity, { label: string; classes: string }> = {
  critical: { label: 'Critical', classes: 'bg-red-500/20 text-red-400 border border-red-500/30' },
  high:     { label: 'High',     classes: 'bg-orange-500/20 text-orange-400 border border-orange-500/30' },
  medium:   { label: 'Medium',   classes: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' },
  low:      { label: 'Low',      classes: 'bg-green-500/20 text-green-400 border border-green-500/30' },
  info:     { label: 'Info',     classes: 'bg-blue-500/20 text-blue-400 border border-blue-500/30' },
}

export default function SeverityBadge({ severity }: SeverityBadgeProps) {
  const key = severity?.toLowerCase() as Severity
  const config = severityConfig[key] ?? { label: severity, classes: 'bg-slate-500/20 text-slate-400 border border-slate-500/30' }

  return (
    <span className={clsx('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium', config.classes)}>
      {config.label}
    </span>
  )
}
