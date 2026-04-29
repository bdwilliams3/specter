import { useEffect, useState, useCallback } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { clsx } from 'clsx'
import { CheckSquare, Square } from 'lucide-react'
import { getRules, getClouds, updateRule, bulkUpdateRules } from '../api/threats'
import DataTable from '../components/shared/DataTable'

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
  suppressed_window?: number
  last_fired_at?: string | null
  enabled?: boolean
  min_asset_confidence?: number
  severity_override?: string | null
  route?: string | null
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
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [saving, setSaving] = useState<string | null>(null)

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
  const thresholds = [0, 3, 5, 8]
  const thresholdLabel = (value: number) => (
    value >= 8 ? 'Confirmed' : value >= 5 ? 'Likely' : value >= 3 ? 'Probable' : 'Any'
  )
  const selectedSet = new Set(selectedIds)
  const toggleSelected = (ruleId: string) => {
    setSelectedIds(prev => prev.includes(ruleId) ? prev.filter(id => id !== ruleId) : [...prev, ruleId])
  }
  const patchRule = async (ruleId: string, patch: Record<string, unknown>) => {
    setSaving(ruleId)
    try {
      await updateRule(ruleId, patch)
      await fetchRules()
    } finally {
      setSaving(null)
    }
  }
  const bulkSetThreshold = async (threshold: number) => {
    if (!selectedIds.length) return
    const selectedRules = rules.filter(rule => selectedIds.includes(rule.rule_id))
    const fires = selectedRules.reduce((sum, rule) => sum + (rule.fires_window ?? 0), 0)
    const suppressed = selectedRules.reduce((sum, rule) => sum + (rule.suppressed_window ?? 0), 0)
    if (!confirm(`Preview: ${selectedIds.length} rules selected. Current 72h window has ${fires} fires and ${suppressed} suppressed events. Save threshold ${thresholdLabel(threshold)}?`)) return
    setSaving('bulk')
    try {
      await bulkUpdateRules(selectedIds.map(rule_id => ({ rule_id, patch: { min_asset_confidence: threshold } })))
      setSelectedIds([])
      await fetchRules()
    } finally {
      setSaving(null)
    }
  }

  const columns: ColumnDef<Rule, unknown>[] = [
    {
      id: 'select',
      header: '',
      enableSorting: false,
      enableColumnFilter: false,
      cell: info => {
        const ruleId = info.row.original.rule_id
        const checked = selectedSet.has(ruleId)
        return (
          <button
            onClick={(e) => { e.stopPropagation(); toggleSelected(ruleId) }}
            className="text-slate-500 hover:text-specter-accent"
            title={checked ? 'Deselect rule' : 'Select rule'}
          >
            {checked ? <CheckSquare size={16} /> : <Square size={16} />}
          </button>
        )
      }
    },
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
      accessorKey: 'severity_override',
      header: 'Severity',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => {
        const row = info.row.original
        const value = row.severity_override || row.severity_default
        return (
          <select
            value={value}
            disabled={saving === row.rule_id}
            onClick={e => e.stopPropagation()}
            onChange={e => patchRule(row.rule_id, { severity_override: e.target.value === row.severity_default ? null : e.target.value })}
            className="bg-specter-bg border border-specter-border rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-specter-accent"
          >
            {['critical', 'high', 'medium', 'low', 'info'].map(sev => (
              <option key={sev} value={sev}>{sev}</option>
            ))}
          </select>
        )
      }
    },
    {
      accessorKey: 'enabled',
      header: 'Enabled',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => {
        const row = info.row.original
        const enabled = row.enabled !== false
        return (
          <button
            onClick={(e) => { e.stopPropagation(); patchRule(row.rule_id, { enabled: !enabled }) }}
            className={clsx(
              'w-10 h-5 rounded-full border transition-colors relative',
              enabled ? 'bg-specter-accent/30 border-specter-accent' : 'bg-specter-border border-slate-700'
            )}
            title={enabled ? 'Disable rule' : 'Enable rule'}
          >
            <span className={clsx(
              'absolute top-0.5 h-3.5 w-3.5 rounded-full bg-white transition-all',
              enabled ? 'left-5' : 'left-0.5'
            )} />
          </button>
        )
      }
    },
    {
      accessorKey: 'min_asset_confidence',
      header: 'Threshold',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => {
        const row = info.row.original
        const value = row.min_asset_confidence ?? 0
        return (
          <select
            value={value}
            disabled={saving === row.rule_id}
            onClick={e => e.stopPropagation()}
            onChange={e => {
              const next = Number(e.target.value)
              const fires = row.fires_window ?? 0
              const suppressed = row.suppressed_window ?? 0
              if (!confirm(`Preview: current 72h window has ${fires} fires and ${suppressed} suppressed events for this rule. Save threshold ${thresholdLabel(next)}?`)) return
              patchRule(row.rule_id, { min_asset_confidence: next })
            }}
            className="bg-specter-bg border border-specter-border rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-specter-accent"
            title={`${thresholdLabel(value)} confidence (${value}+)`}
          >
            {thresholds.map(t => (
              <option key={t} value={t}>{thresholdLabel(t)} {t > 0 ? `${t}+` : ''}</option>
            ))}
          </select>
        )
      }
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
      accessorKey: 'route',
      header: 'Route',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => {
        const row = info.row.original
        return (
          <select
            value={row.route || ''}
            disabled={saving === row.rule_id}
            onClick={e => e.stopPropagation()}
            onChange={e => patchRule(row.rule_id, { route: e.target.value || null })}
            className="bg-specter-bg border border-specter-border rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-specter-accent"
          >
            <option value="">Default</option>
            <option value="siem">SIEM</option>
            <option value="review">Review</option>
            <option value="silent">Silent</option>
          </select>
        )
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
      accessorKey: 'suppressed_window',
      header: 'Suppressed',
      enableSorting: true,
      enableColumnFilter: false,
      cell: info => {
        const v = (info.getValue() as number) ?? 0
        return v > 0
          ? <span className="text-yellow-400 font-semibold">{v}</span>
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

      {selectedIds.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 border border-specter-border bg-specter-surface rounded px-3 py-2">
          <span className="text-xs text-slate-400">{selectedIds.length} selected</span>
          <div className="flex items-center gap-1">
            {thresholds.map(t => (
              <button
                key={t}
                disabled={saving === 'bulk'}
                onClick={() => bulkSetThreshold(t)}
                className="px-2.5 py-1 text-xs rounded border border-specter-border text-slate-300 hover:text-white hover:border-specter-accent disabled:opacity-50"
                title={`Set selected rules to ${thresholdLabel(t)} threshold`}
              >
                {thresholdLabel(t)} {t > 0 ? `${t}+` : ''}
              </button>
            ))}
          </div>
          <button
            onClick={() => setSelectedIds([])}
            className="ml-auto text-xs text-slate-500 hover:text-slate-200"
          >
            Clear
          </button>
        </div>
      )}

      <DataTable
        columns={columns}
        data={rules}
        isLoading={isLoading}
      />
    </div>
  )
}
