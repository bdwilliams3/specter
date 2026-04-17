import { useEffect, useState, useCallback } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { clsx } from 'clsx'
import { getRules, getClouds } from '../api/threats'
import DataTable from '../components/shared/DataTable'
import SeverityBadge from '../components/shared/SeverityBadge'

interface Rule {
  rule_id: string
  threat_name: string
  cloud: string
  source: string
  severity_default: string
  category: string
  mitre_atlas?: string
  description?: string
  fires_window: number
  last_fired_at?: string | null
}

interface Cloud {
  id: string
  label: string
  enabled: boolean
}

export default function Rules() {
  const [clouds, setClouds] = useState<Cloud[]>([])
  const [activeCloud, setActiveCloud] = useState<string>('kubernetes')
  const [rules, setRules] = useState<Rule[]>([])
  const [isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    getClouds()
      .then(d => setClouds(d.items ?? []))
      .catch(() => setClouds([]))
  }, [])

  const fetchRules = useCallback(async () => {
    setIsLoading(true)
    try {
      const data = await getRules({ cloud: activeCloud })
      setRules(data.items ?? [])
    } catch {
      setRules([])
    } finally {
      setIsLoading(false)
    }
  }, [activeCloud])

  useEffect(() => { fetchRules() }, [fetchRules])

  const dash = <span className="text-slate-500">—</span>

  const columns: ColumnDef<Rule, unknown>[] = [
    {
      accessorKey: 'threat_name',
      header: 'Rule',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => {
        const row = info.row.original
        return (
          <div className="flex flex-col">
            <span className="text-white font-medium">{row.threat_name}</span>
            <span className="text-[11px] text-slate-500 font-mono">{row.rule_id}</span>
          </div>
        )
      }
    },
    {
      accessorKey: 'source',
      header: 'Source',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => {
        const v = info.getValue() as string
        return (
          <span className="font-mono text-[11px] uppercase tracking-wider text-slate-400 bg-specter-border/50 px-1.5 py-0.5 rounded">
            {v}
          </span>
        )
      }
    },
    {
      accessorKey: 'severity_default',
      header: 'Severity',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => <SeverityBadge severity={info.getValue() as string} />
    },
    {
      accessorKey: 'category',
      header: 'Category',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => <span className="text-slate-300">{(info.getValue() as string) ?? '—'}</span>
    },
    {
      accessorKey: 'mitre_atlas',
      header: 'Mitre Mapping',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => {
        const v = info.getValue() as string | undefined
        return v
          ? <span className="font-mono text-xs text-indigo-400 bg-indigo-500/10 px-1.5 py-0.5 rounded">{v}</span>
          : dash
      }
    },
    {
      accessorKey: 'fires_window',
      header: 'Fires (72h)',
      enableSorting: true,
      enableColumnFilter: false,
      cell: info => {
        const v = (info.getValue() as number) ?? 0
        return v > 0
          ? <span className="text-specter-accent font-semibold">{v}</span>
          : <span className="text-slate-500">0</span>
      }
    },
    {
      accessorKey: 'last_fired_at',
      header: 'Last Fired',
      enableSorting: true,
      enableColumnFilter: false,
      cell: info => {
        const v = info.getValue() as string | null | undefined
        return <span className="text-slate-400 text-xs">{v ? new Date(v).toLocaleString() : '—'}</span>
      }
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      {/* Cloud filter tabs */}
      <div className="flex items-center gap-1 border-b border-specter-border overflow-x-auto">
        {clouds.map(c => {
          const isActive = c.id === activeCloud
          return (
            <button
              key={c.id}
              onClick={() => c.enabled && setActiveCloud(c.id)}
              disabled={!c.enabled}
              className={clsx(
                'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors whitespace-nowrap',
                isActive && c.enabled
                  ? 'border-specter-accent text-specter-accent'
                  : c.enabled
                    ? 'border-transparent text-slate-400 hover:text-slate-200'
                    : 'border-transparent text-slate-600 cursor-not-allowed'
              )}
            >
              {c.label}
              {!c.enabled && (
                <span className="ml-2 text-[10px] uppercase tracking-wider text-slate-600 bg-specter-border/50 px-1.5 py-0.5 rounded">
                  soon
                </span>
              )}
            </button>
          )
        })}
      </div>

      <DataTable
        columns={columns}
        data={rules}
        isLoading={isLoading}
      />
    </div>
  )
}
