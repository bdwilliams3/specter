import { memo } from 'react'
import { Handle, Position, type NodeProps } from 'reactflow'
import { Shield, Cloud, Server, Bot } from 'lucide-react'
import { clsx } from 'clsx'

export interface AssetNodeData {
  name: string
  asset_type: string
  provider: string
  provider_color?: string
  risk_score?: number
  namespace?: string
}

function getRiskColor(score?: number) {
  if (score === undefined || score === null) return 'text-slate-400'
  if (score < 30) return 'text-green-400'
  if (score < 60) return 'text-yellow-400'
  return 'text-red-400'
}

function getRiskBg(score?: number) {
  if (score === undefined || score === null) return 'bg-slate-500/20'
  if (score < 30) return 'bg-green-500/20'
  if (score < 60) return 'bg-yellow-500/20'
  return 'bg-red-500/20'
}

function AssetIcon({ type }: { type: string }) {
  const cls = 'w-5 h-5'
  switch (type?.toLowerCase()) {
    case 'mcp_server': return <Shield className={cls} />
    case 'cloud':      return <Cloud className={cls} />
    case 'k8s':
    case 'kubernetes': return <Server className={cls} />
    case 'agentic':
    case 'agent':      return <Bot className={cls} />
    default:           return <Server className={cls} />
  }
}

function AssetNode({ data, selected }: NodeProps<AssetNodeData>) {
  const name = data.name?.length > 20 ? data.name.slice(0, 20) + '…' : (data.name ?? 'Unknown')
  const borderColor = data.provider_color ?? '#2a2d3e'

  return (
    <div
      className={clsx(
        'bg-[#1a1d27] rounded-lg px-3 py-2.5 min-w-[150px] max-w-[180px] shadow-lg border-2 transition-shadow',
        selected ? 'shadow-specter-accent/40 shadow-lg' : ''
      )}
      style={{ borderColor: selected ? '#6366f1' : borderColor }}
    >
      <Handle type="target" position={Position.Top} className="!bg-specter-accent !border-specter-border !w-2 !h-2" />

      <div className="flex items-start gap-2">
        <div className="shrink-0 text-slate-300 mt-0.5">
          <AssetIcon type={data.asset_type} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-white text-xs font-semibold leading-tight truncate" title={data.name}>
            {name}
          </p>
          {data.namespace && (
            <p className="text-slate-500 text-[10px] truncate mt-0.5">{data.namespace}</p>
          )}
        </div>
        {data.risk_score !== undefined && (
          <div className={clsx('shrink-0 flex items-center justify-center w-6 h-6 rounded-full text-[10px] font-bold', getRiskBg(data.risk_score), getRiskColor(data.risk_score))}>
            {Math.round(data.risk_score)}
          </div>
        )}
      </div>

      {data.provider && (
        <div className="mt-2 pt-2 border-t border-[#2a2d3e]">
          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-700/50 text-slate-400">
            {data.provider}
          </span>
        </div>
      )}

      <Handle type="source" position={Position.Bottom} className="!bg-specter-accent !border-specter-border !w-2 !h-2" />
    </div>
  )
}

export default memo(AssetNode)
