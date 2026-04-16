import { useEffect, useState, useCallback } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { Search, Trash2, X } from 'lucide-react'
import { getAssets, deleteAsset } from '../api/assets'
import DataTable from '../components/shared/DataTable'
import ExportMenu from '../components/shared/ExportMenu'

interface Asset {
  id: string
  name: string
  asset_type: string
  provider: string
  namespace?: string
  risk_score?: number
  last_seen?: string
  description?: string
  tags?: string[]
  [key: string]: unknown
}

const PAGE_SIZE = 20

export default function Inventory() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [isLoading, setIsLoading] = useState(false)
  const [search, setSearch] = useState('')
  const [assetType, setAssetType] = useState('')
  const [provider, setProvider] = useState('')
  const [selected, setSelected] = useState<Asset | null>(null)

  const fetchAssets = useCallback(async () => {
    setIsLoading(true)
    try {
      const params: Record<string, unknown> = { page, limit: PAGE_SIZE }
      if (search) params.search = search
      if (assetType) params.asset_type = assetType
      if (provider) params.provider = provider
      const data = await getAssets(params)
      const items = Array.isArray(data) ? data : data.items ?? []
      setAssets(items)
      setTotal(Array.isArray(data) ? data.length : data.total ?? items.length)
    } catch {
      setAssets([])
    } finally {
      setIsLoading(false)
    }
  }, [page, search, assetType, provider])

  useEffect(() => { fetchAssets() }, [fetchAssets])

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm('Delete this asset?')) return
    await deleteAsset(id).catch(() => {})
    fetchAssets()
  }

  const columns: ColumnDef<Asset, unknown>[] = [
    { accessorKey: 'name',       header: 'Name',      cell: info => <span className="text-white font-medium">{info.getValue() as string}</span> },
    { accessorKey: 'asset_type', header: 'Type',      cell: info => <span className="text-slate-300 capitalize">{(info.getValue() as string)?.replace('_', ' ')}</span> },
    { accessorKey: 'provider',   header: 'Provider',  cell: info => <span className="text-slate-300">{info.getValue() as string}</span> },
    { accessorKey: 'namespace',  header: 'Namespace', cell: info => <span className="text-slate-400 font-mono text-xs">{(info.getValue() as string) ?? '—'}</span> },
    {
      accessorKey: 'risk_score',
      header: 'Risk Score',
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
      cell: info => {
        const v = info.getValue() as string | undefined
        return <span className="text-slate-400 text-xs">{v ? new Date(v).toLocaleString() : '—'}</span>
      }
    },
    {
      id: 'actions',
      header: 'Actions',
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
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
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
        <select
          value={assetType}
          onChange={e => { setAssetType(e.target.value); setPage(1) }}
          className="bg-specter-surface border border-specter-border text-slate-300 rounded px-3 py-2 text-sm focus:outline-none focus:border-specter-accent"
        >
          <option value="">All Types</option>
          <option value="mcp_server">MCP Server</option>
          <option value="cloud">Cloud</option>
          <option value="k8s">Kubernetes</option>
          <option value="agentic">Agentic</option>
        </select>
        <select
          value={provider}
          onChange={e => { setProvider(e.target.value); setPage(1) }}
          className="bg-specter-surface border border-specter-border text-slate-300 rounded px-3 py-2 text-sm focus:outline-none focus:border-specter-accent"
        >
          <option value="">All Providers</option>
          <option value="aws">AWS</option>
          <option value="gcp">GCP</option>
          <option value="azure">Azure</option>
          <option value="openai">OpenAI</option>
          <option value="anthropic">Anthropic</option>
        </select>
        <div className="ml-auto">
          <ExportMenu entity="assets" />
        </div>
      </div>

      <DataTable
        columns={columns}
        data={assets}
        isLoading={isLoading}
        onRowClick={setSelected}
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
