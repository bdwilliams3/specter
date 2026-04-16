import { useEffect, useState, useCallback } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { X } from 'lucide-react'
import { getThreats } from '../api/threats'
import DataTable from '../components/shared/DataTable'
import SeverityBadge from '../components/shared/SeverityBadge'
import ExportMenu from '../components/shared/ExportMenu'

interface Threat {
  id: string
  title: string
  severity: string
  category?: string
  mitre_atlas?: string
  detected_at?: string
  description?: string
  raw_evidence?: unknown
  asset_id?: string
}

const PAGE_SIZE = 20

export default function Threats() {
  const [threats, setThreats] = useState<Threat[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [isLoading, setIsLoading] = useState(false)
  const [severity, setSeverity] = useState('')
  const [category, setCategory] = useState('')
  const [selected, setSelected] = useState<Threat | null>(null)

  const fetchThreats = useCallback(async () => {
    setIsLoading(true)
    try {
      const params: Record<string, unknown> = { page, limit: PAGE_SIZE }
      if (severity) params.severity = severity
      if (category) params.category = category
      const data = await getThreats(params)
      const items = Array.isArray(data) ? data : data.items ?? []
      setThreats(items)
      setTotal(Array.isArray(data) ? data.length : data.total ?? items.length)
    } catch {
      setThreats([])
    } finally {
      setIsLoading(false)
    }
  }, [page, severity, category])

  useEffect(() => { fetchThreats() }, [fetchThreats])

  const columns: ColumnDef<Threat, unknown>[] = [
    {
      accessorKey: 'title',
      header: 'Title',
      cell: info => <span className="text-white font-medium">{info.getValue() as string}</span>
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: info => <SeverityBadge severity={info.getValue() as string} />
    },
    {
      accessorKey: 'category',
      header: 'Category',
      cell: info => <span className="text-slate-300">{(info.getValue() as string) ?? '—'}</span>
    },
    {
      accessorKey: 'mitre_atlas',
      header: 'MITRE ATLAS',
      cell: info => {
        const v = info.getValue() as string | undefined
        return v
          ? <span className="font-mono text-xs text-indigo-400 bg-indigo-500/10 px-1.5 py-0.5 rounded">{v}</span>
          : <span className="text-slate-500">—</span>
      }
    },
    {
      accessorKey: 'detected_at',
      header: 'Detected At',
      cell: info => {
        const v = info.getValue() as string | undefined
        return <span className="text-slate-400 text-xs">{v ? new Date(v).toLocaleString() : '—'}</span>
      }
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={severity}
          onChange={e => { setSeverity(e.target.value); setPage(1) }}
          className="bg-specter-surface border border-specter-border text-slate-300 rounded px-3 py-2 text-sm focus:outline-none focus:border-specter-accent"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select
          value={category}
          onChange={e => { setCategory(e.target.value); setPage(1) }}
          className="bg-specter-surface border border-specter-border text-slate-300 rounded px-3 py-2 text-sm focus:outline-none focus:border-specter-accent"
        >
          <option value="">All Categories</option>
          <option value="prompt_injection">Prompt Injection</option>
          <option value="data_exfiltration">Data Exfiltration</option>
          <option value="privilege_escalation">Privilege Escalation</option>
          <option value="lateral_movement">Lateral Movement</option>
          <option value="supply_chain">Supply Chain</option>
          <option value="model_manipulation">Model Manipulation</option>
        </select>
        <div className="ml-auto">
          <ExportMenu entity="threats" />
        </div>
      </div>

      <DataTable
        columns={columns}
        data={threats}
        isLoading={isLoading}
        onRowClick={setSelected}
        pagination={{ page, pageSize: PAGE_SIZE, total, onPageChange: setPage }}
      />

      {/* Slide-over drawer */}
      {selected && (
        <div className="fixed inset-0 z-40 flex justify-end">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setSelected(null)} />
          <div className="relative z-10 w-full max-w-lg bg-specter-surface border-l border-specter-border shadow-2xl flex flex-col overflow-y-auto">
            <div className="flex items-center justify-between px-6 py-4 border-b border-specter-border sticky top-0 bg-specter-surface z-10">
              <div className="flex items-center gap-3">
                <h2 className="text-white font-semibold text-base">Threat Detail</h2>
                <SeverityBadge severity={selected.severity} />
              </div>
              <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-white transition-colors">
                <X size={18} />
              </button>
            </div>
            <div className="flex-1 px-6 py-5 flex flex-col gap-5">
              <div>
                <h3 className="text-xl font-bold text-white">{selected.title}</h3>
                <p className="text-slate-400 text-sm mt-2 leading-relaxed">{selected.description ?? 'No description available.'}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: 'Category',    value: selected.category ?? '—' },
                  { label: 'MITRE ATLAS', value: selected.mitre_atlas ?? '—' },
                  { label: 'Asset ID',    value: selected.asset_id ?? '—' },
                  { label: 'Detected At', value: selected.detected_at ? new Date(selected.detected_at).toLocaleString() : '—' },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</p>
                    <p className="text-sm text-slate-200 font-medium font-mono">{value}</p>
                  </div>
                ))}
              </div>

              {selected.raw_evidence != null && (
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Raw Evidence</p>
                  <pre className="bg-specter-bg border border-specter-border rounded p-3 text-xs text-slate-300 overflow-x-auto max-h-72 font-mono whitespace-pre-wrap">
                    {typeof selected.raw_evidence === 'string'
                      ? selected.raw_evidence
                      : JSON.stringify(selected.raw_evidence as object, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
