import { useEffect, useState, useCallback } from 'react'
import { type Node, type Edge, useReactFlow, ReactFlowProvider } from 'reactflow'
import { X, Maximize2, RefreshCw } from 'lucide-react'
import { getGraph } from '../api/graph'
import TopologyGraph from '../components/graph/TopologyGraph'
import SeverityBadge from '../components/shared/SeverityBadge'
import { type AssetNodeData } from '../components/graph/AssetNode'

interface AssetDetail {
  id: string
  name: string
  asset_type: string
  provider: string
  namespace?: string
  risk_score?: number
  description?: string
  tags?: string[]
  threats?: Array<{ id: string; title: string; severity: string }>
  vulnerabilities?: Array<{ id: string; title: string; severity: string }>
}

const PROVIDERS = ['aws', 'gcp', 'azure', 'openai', 'anthropic', 'other']
const ASSET_TYPES = ['mcp_server', 'cloud', 'k8s', 'agentic']

function GraphInner() {
  const [nodes, setNodes] = useState<Node<AssetNodeData>[]>([])
  const [edges, setEdges] = useState<Edge[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [selected, setSelected] = useState<AssetDetail | null>(null)
  const [providerFilter, setProviderFilter] = useState<Set<string>>(new Set())
  const [typeFilter, setTypeFilter] = useState<Set<string>>(new Set())
  const { fitView } = useReactFlow()

  const fetchGraph = useCallback(async () => {
    setIsLoading(true)
    try {
      const data = await getGraph()
      const rawNodes: Node<AssetNodeData>[] = (data.nodes ?? []).map((n: Node<AssetNodeData>) => ({
        ...n,
        type: 'assetNode',
      }))
      setNodes(rawNodes)
      setEdges(data.edges ?? [])
    } catch {
      setNodes([])
      setEdges([])
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => { fetchGraph() }, [fetchGraph])

  const toggleFilter = <T extends string>(set: Set<T>, val: T, setter: (s: Set<T>) => void) => {
    const next = new Set(set)
    if (next.has(val)) next.delete(val)
    else next.add(val)
    setter(next)
  }

  const filteredNodes = nodes.filter(n => {
    if (providerFilter.size > 0 && !providerFilter.has(n.data.provider?.toLowerCase())) return false
    if (typeFilter.size > 0 && !typeFilter.has(n.data.asset_type?.toLowerCase())) return false
    return true
  })

  const filteredNodeIds = new Set(filteredNodes.map(n => n.id))
  const filteredEdges = edges.filter(e => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target))

  const handleNodeClick = useCallback((node: Node<AssetNodeData>) => {
    setSelected({
      id: node.id,
      name: node.data.name,
      asset_type: node.data.asset_type,
      provider: node.data.provider,
      namespace: node.data.namespace,
      risk_score: node.data.risk_score,
    })
  }, [])

  return (
    <div className="flex h-[calc(100vh-120px)] gap-0 rounded-lg border border-specter-border overflow-hidden">
      {/* Left filter panel */}
      <div className="w-52 shrink-0 bg-specter-surface border-r border-specter-border flex flex-col overflow-y-auto">
        <div className="px-4 py-3 border-b border-specter-border">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Filters</p>
        </div>

        <div className="px-4 py-3 border-b border-specter-border">
          <p className="text-xs text-slate-500 mb-2 font-medium">Provider</p>
          <div className="flex flex-col gap-1.5">
            {PROVIDERS.map(p => (
              <label key={p} className="flex items-center gap-2 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={providerFilter.has(p)}
                  onChange={() => toggleFilter(providerFilter, p, setProviderFilter)}
                  className="w-3.5 h-3.5 accent-indigo-500"
                />
                <span className="text-xs text-slate-300 capitalize group-hover:text-white transition-colors">{p}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="px-4 py-3">
          <p className="text-xs text-slate-500 mb-2 font-medium">Asset Type</p>
          <div className="flex flex-col gap-1.5">
            {ASSET_TYPES.map(t => (
              <label key={t} className="flex items-center gap-2 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={typeFilter.has(t)}
                  onChange={() => toggleFilter(typeFilter, t, setTypeFilter)}
                  className="w-3.5 h-3.5 accent-indigo-500"
                />
                <span className="text-xs text-slate-300 capitalize group-hover:text-white transition-colors">{t.replace('_', ' ')}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="mt-auto px-4 py-3 border-t border-specter-border">
          <button
            onClick={fetchGraph}
            disabled={isLoading}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
          >
            <RefreshCw size={12} className={isLoading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Graph canvas */}
      <div className="flex-1 relative">
        <button
          onClick={() => fitView({ padding: 0.2 })}
          className="absolute top-3 right-3 z-10 flex items-center gap-1.5 px-2.5 py-1.5 text-xs bg-specter-surface border border-specter-border text-slate-300 rounded hover:border-specter-accent hover:text-white transition-colors shadow"
        >
          <Maximize2 size={12} />
          Fit to screen
        </button>

        {isLoading && (
          <div className="absolute inset-0 z-20 flex items-center justify-center bg-specter-bg/60">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <RefreshCw size={16} className="animate-spin" />
              Loading topology…
            </div>
          </div>
        )}

        <TopologyGraph nodes={filteredNodes} edges={filteredEdges} onNodeClick={handleNodeClick} />
      </div>

      {/* Right detail panel */}
      {selected && (
        <div className="w-72 shrink-0 bg-specter-surface border-l border-specter-border flex flex-col overflow-y-auto">
          <div className="flex items-center justify-between px-4 py-3 border-b border-specter-border">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Asset Detail</p>
            <button onClick={() => setSelected(null)} className="text-slate-500 hover:text-white transition-colors">
              <X size={14} />
            </button>
          </div>
          <div className="px-4 py-4 flex flex-col gap-4">
            <div>
              <h3 className="text-white font-semibold text-sm">{selected.name}</h3>
              <p className="text-slate-500 text-xs mt-0.5">{selected.id}</p>
            </div>
            <div className="grid grid-cols-1 gap-3">
              {[
                { label: 'Type',       value: selected.asset_type?.replace('_', ' ') },
                { label: 'Provider',   value: selected.provider },
                { label: 'Namespace',  value: selected.namespace ?? '—' },
                { label: 'Risk Score', value: selected.risk_score !== undefined ? String(selected.risk_score) : '—' },
              ].map(({ label, value }) => (
                <div key={label} className="flex justify-between items-center">
                  <span className="text-xs text-slate-500">{label}</span>
                  <span className="text-xs text-slate-200 font-medium capitalize">{value}</span>
                </div>
              ))}
            </div>
            {selected.threats && selected.threats.length > 0 && (
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Threats</p>
                <div className="flex flex-col gap-1.5">
                  {selected.threats.map(t => (
                    <div key={t.id} className="flex items-center justify-between gap-2 p-2 bg-specter-bg rounded">
                      <span className="text-xs text-slate-300 truncate">{t.title}</span>
                      <SeverityBadge severity={t.severity} />
                    </div>
                  ))}
                </div>
              </div>
            )}
            {selected.vulnerabilities && selected.vulnerabilities.length > 0 && (
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Vulnerabilities</p>
                <div className="flex flex-col gap-1.5">
                  {selected.vulnerabilities.map(v => (
                    <div key={v.id} className="flex items-center justify-between gap-2 p-2 bg-specter-bg rounded">
                      <span className="text-xs text-slate-300 truncate">{v.title}</span>
                      <SeverityBadge severity={v.severity} />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default function Graph() {
  return (
    <ReactFlowProvider>
      <GraphInner />
    </ReactFlowProvider>
  )
}
