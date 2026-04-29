import { useEffect, useState, useCallback } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { Search, Trash2, X } from 'lucide-react'
import { getAssets, getAssetSignals, triageAsset, deleteAsset } from '../api/assets'
import DataTable from '../components/shared/DataTable'
import ExportMenu from '../components/shared/ExportMenu'

interface Asset {
  id: string
  name: string
  asset_type: string
  provider: string
  namespace?: string
  risk_score?: number
  ai_confidence?: number
  triage_state?: string | null
  triage_reason?: string | null
  confidence_ceiling?: number | null
  triage_updated_by?: string | null
  triage_updated_at?: string | null
  last_seen?: string
  description?: string
  tags?: string[]
  [key: string]: unknown
}

interface AssetSignal {
  id: string
  signal_type: string
  source: string
  value: string
  weight: number
  observed_at?: string
}

const PAGE_SIZE = 20

export default function Inventory() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [isLoading, setIsLoading] = useState(false)
  const [search, setSearch]   = useState('')
  const [selected, setSelected] = useState<Asset | null>(null)
  const [signals, setSignals] = useState<AssetSignal[]>([])
  const [scoreFilter, setScoreFilter] = useState<'all' | 'confirmed' | 'tier1'>('all')
  const [triageReason, setTriageReason] = useState('')
  const [ceiling, setCeiling] = useState(5)

  const fetchAssets = useCallback(async () => {
    setIsLoading(true)
    try {
      const params: Record<string, unknown> = { page, page_size: PAGE_SIZE }
      if (search) params.search = search
      const data = await getAssets(params)
      const rawItems = Array.isArray(data) ? data : data.items ?? []
      const items = rawItems.filter((asset: Asset) => {
        if (scoreFilter === 'confirmed') return (asset.ai_confidence ?? 0) >= 8
        if (scoreFilter === 'tier1') {
          const metadata = asset.metadata_ as { ai_signals?: AssetSignal[] } | undefined
          return (metadata?.ai_signals ?? []).some(signal => signal.signal_type === 'ai_provider_endpoint' || signal.weight >= 5)
        }
        return true
      })
      setAssets(items)
      setTotal(Array.isArray(data) ? items.length : data.total ?? items.length)
    } catch {
      setAssets([])
    } finally {
      setIsLoading(false)
    }
  }, [page, search, scoreFilter])

  useEffect(() => { fetchAssets() }, [fetchAssets])

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm('Delete this asset?')) return
    await deleteAsset(id).catch(() => {})
    fetchAssets()
  }

  const confidenceBucket = (score = 0) => (
    score >= 8 ? 'Confirmed' : score >= 5 ? 'Likely' : score >= 3 ? 'Probable' : 'Speculative'
  )
  const scoreColor = (score = 0) => (
    score >= 8 ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
      : score >= 5 ? 'bg-sky-500/15 text-sky-300 border-sky-500/30'
        : score >= 3 ? 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30'
          : 'bg-slate-700/40 text-slate-300 border-slate-600'
  )
  const openAsset = async (asset: Asset) => {
    setSelected(asset)
    setTriageReason('')
    setCeiling(Number(asset.confidence_ceiling ?? 5))
    setSignals([])
    try {
      const data = await getAssetSignals(asset.id)
      setSignals(data.items ?? [])
    } catch {
      setSignals([])
    }
  }
  const applyTriage = async (action: 'confirm' | 'downgrade' | 'dismiss') => {
    if (!selected || triageReason.trim().length < 3) return
    const updated = await triageAsset(selected.id, {
      action,
      reason: triageReason.trim(),
      confidence_ceiling: action === 'downgrade' ? ceiling : null,
    }).catch(() => null)
    if (updated) {
      setSelected(updated)
      setAssets(prev => prev.map(asset => asset.id === updated.id ? updated : asset))
      setTriageReason('')
    }
  }

  const columns: ColumnDef<Asset, unknown>[] = [
    { accessorKey: 'name',       header: 'Name',      enableSorting: true, enableColumnFilter: true,  filterFn: 'multiSelect', cell: info => <span className="text-white font-medium">{info.getValue() as string}</span> },
    { accessorKey: 'asset_type', header: 'Type',      enableSorting: true, enableColumnFilter: true,  filterFn: 'multiSelect', cell: info => <span className="text-slate-300 capitalize">{(info.getValue() as string)?.replace(/_/g, ' ')}</span> },
    { accessorKey: 'provider',   header: 'Provider',  enableSorting: true, enableColumnFilter: true,  filterFn: 'multiSelect', cell: info => <span className="text-slate-300">{info.getValue() as string}</span> },
    { accessorKey: 'namespace',  header: 'Namespace', enableSorting: true, enableColumnFilter: true,  filterFn: 'multiSelect', cell: info => <span className="text-slate-400 font-mono text-xs">{(info.getValue() as string) ?? '—'}</span> },
    {
      accessorKey: 'ai_confidence',
      header: 'AI Score',
      enableSorting: true,
      enableColumnFilter: false,
      cell: info => {
        const score = Number(info.getValue() ?? 0)
        return (
          <span className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-semibold ${scoreColor(score)}`}>
            {score.toFixed(1)}
            <span className="font-normal">{confidenceBucket(score)}</span>
          </span>
        )
      }
    },
    {
      accessorKey: 'risk_score',
      header: 'Risk Score',
      enableSorting: true,
      enableColumnFilter: false,
      cell: info => {
        const v = info.getValue() as number | undefined
        if (v === undefined || v === null) return <span className="text-slate-500">—</span>
        const color = v < 30 ? 'text-green-400' : v < 60 ? 'text-yellow-400' : 'text-red-400'
        return <span className={`font-semibold ${color}`}>{v}</span>
      }
    },
    {
      accessorKey: 'last_seen',
      header: 'Last Seen',
      enableSorting: true,
      enableColumnFilter: false,
      cell: info => {
        const v = info.getValue() as string | undefined
        return <span className="text-slate-400 text-xs">{v ? new Date(v).toLocaleString() : '—'}</span>
      }
    },
    {
      id: 'actions',
      header: '',
      enableSorting: false,
      enableColumnFilter: false,
      cell: info => (
        <button
          onClick={(e) => handleDelete(info.row.original.id, e)}
          className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
          title="Delete asset"
        >
          <Trash2 size={14} />
        </button>
      )
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-3">
        <div className="relative flex-1 min-w-48 max-w-xs">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search assets…"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1) }}
            className="w-full bg-specter-surface border border-specter-border text-slate-200 rounded pl-8 pr-3 py-2 text-sm placeholder:text-slate-600 focus:outline-none focus:border-specter-accent"
          />
        </div>
        <div className="ml-auto">
          <ExportMenu entity="assets" />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1 border-b border-specter-border">
        {[
          { id: 'all', label: 'All' },
          { id: 'confirmed', label: 'Confirmed' },
          { id: 'tier1', label: 'Tier 1 Signal' },
        ].map(item => (
          <button
            key={item.id}
            onClick={() => { setScoreFilter(item.id as typeof scoreFilter); setPage(1) }}
            className={`px-3 py-2 text-sm border-b-2 -mb-px ${
              scoreFilter === item.id
                ? 'border-specter-accent text-specter-accent'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {item.label}
          </button>
        ))}
      </div>

      <DataTable
        columns={columns}
        data={assets}
        isLoading={isLoading}
        onRowClick={openAsset}
        pagination={{ page, pageSize: PAGE_SIZE, total, onPageChange: setPage }}
      />

      {/* Slide-over drawer */}
      {selected && (
        <div className="fixed inset-0 z-40 flex justify-end">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setSelected(null)} />
          <div className="relative z-10 w-full max-w-md bg-specter-surface border-l border-specter-border shadow-2xl flex flex-col overflow-y-auto">
            <div className="flex items-center justify-between px-6 py-4 border-b border-specter-border sticky top-0 bg-specter-surface z-10">
              <h2 className="text-white font-semibold text-base">Asset Detail</h2>
              <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-white transition-colors">
                <X size={18} />
              </button>
            </div>
            <div className="flex-1 px-6 py-5 flex flex-col gap-5">
              <div>
                <h3 className="text-xl font-bold text-white">{selected.name}</h3>
                <p className="text-slate-400 text-sm mt-1">{selected.description ?? 'No description available.'}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: 'Type',      value: selected.asset_type?.replace('_', ' ') },
                  { label: 'Provider',  value: selected.provider },
                  { label: 'Namespace', value: selected.namespace ?? '—' },
                  { label: 'AI Score', value: `${Number(selected.ai_confidence ?? 0).toFixed(1)} ${confidenceBucket(selected.ai_confidence)}` },
                  { label: 'Risk Score', value: selected.risk_score?.toString() ?? '—' },
                  { label: 'Last Seen', value: selected.last_seen ? new Date(selected.last_seen).toLocaleString() : '—' },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</p>
                    <p className="text-sm text-slate-200 font-medium capitalize">{value}</p>
                  </div>
                ))}
              </div>
              {selected.tags && selected.tags.length > 0 && (
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Tags</p>
                  <div className="flex flex-wrap gap-2">
                    {selected.tags.map((tag) => (
                      <span key={tag} className="px-2 py-0.5 text-xs bg-specter-border rounded text-slate-300">{tag}</span>
                    ))}
                  </div>
                </div>
              )}
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Triage</p>
                <div className="border border-specter-border rounded p-3 bg-specter-bg flex flex-col gap-3">
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-slate-400">State</span>
                    <span className="text-slate-200 capitalize">{selected.triage_state ?? 'unreviewed'}</span>
                    {selected.confidence_ceiling != null && (
                      <span className="ml-auto text-xs text-yellow-300">Ceiling {selected.confidence_ceiling}</span>
                    )}
                  </div>
                  {selected.triage_reason && (
                    <p className="text-xs text-slate-400">{selected.triage_reason}</p>
                  )}
                  <textarea
                    value={triageReason}
                    onChange={e => setTriageReason(e.target.value)}
                    placeholder="Reason required"
                    className="min-h-16 bg-specter-surface border border-specter-border rounded px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-specter-accent"
                  />
                  <div className="flex items-center gap-2">
                    <select
                      value={ceiling}
                      onChange={e => setCeiling(Number(e.target.value))}
                      className="bg-specter-surface border border-specter-border rounded px-2 py-1.5 text-xs text-slate-200"
                    >
                      {[2, 3, 5, 8].map(v => <option key={v} value={v}>Ceiling {v}</option>)}
                    </select>
                    <button onClick={() => applyTriage('confirm')} className="px-2.5 py-1.5 text-xs rounded border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10">Confirm</button>
                    <button onClick={() => applyTriage('downgrade')} className="px-2.5 py-1.5 text-xs rounded border border-yellow-500/30 text-yellow-300 hover:bg-yellow-500/10">Downgrade</button>
                    <button onClick={() => applyTriage('dismiss')} className="px-2.5 py-1.5 text-xs rounded border border-red-500/30 text-red-300 hover:bg-red-500/10">Dismiss</button>
                  </div>
                </div>
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">AI Signals</p>
                <div className="flex flex-col gap-2">
                  {signals.length === 0 ? (
                    <p className="text-sm text-slate-500">No signal breakdown available.</p>
                  ) : signals.map(signal => (
                    <div key={signal.id} className="border border-specter-border rounded p-3 bg-specter-bg">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-slate-200 font-medium">{signal.signal_type.replace(/_/g, ' ')}</span>
                        <span className="ml-auto text-xs text-specter-accent font-semibold">+{signal.weight}</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1 break-all">{signal.value}</p>
                      <p className="text-[11px] text-slate-600 mt-1">{signal.source}{signal.observed_at ? ` · ${new Date(signal.observed_at).toLocaleString()}` : ''}</p>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Raw Data</p>
                <pre className="bg-specter-bg border border-specter-border rounded p-3 text-xs text-slate-300 overflow-x-auto max-h-64 font-mono">
                  {JSON.stringify(selected, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
