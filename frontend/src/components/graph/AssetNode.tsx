import { memo } from 'react'
import { Handle, Position, type NodeProps } from 'reactflow'
import { Shield, Cloud, Server, Bot, Cpu, Layers, GitBranch, Database } from 'lucide-react'
import { clsx } from 'clsx'

export interface AssetNodeData {
  label: string
  asset_type: string
  provider: string
  risk_score?: number
  namespace?: string
  cluster?: string
  color?: string
}

const RISK_RING: Record<string, string> = {
  low:      'text-green-400 bg-green-500/15',
  medium:   'text-yellow-400 bg-yellow-500/15',
  high:     'text-orange-400 bg-orange-500/15',
  critical: 'text-red-400 bg-red-500/15',
}

const PROVIDER_BADGE: Record<string, string> = {
  k8s:   'bg-blue-500/15 text-blue-400',
  azure: 'bg-violet-500/15 text-violet-400',
  aws:   'bg-orange-500/15 text-orange-400',
  gcp:   'bg-emerald-500/15 text-emerald-400',
}

function riskLevel(score?: number): string {
  if (score == null) return 'low'
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

function AssetIcon({ type }: { type: string }) {
  const cls = 'w-4 h-4 shrink-0'
  switch (type) {
    case 'mcp_server':          return <Shield className={cls} />
    case 'agentic_framework':   return <Bot className={cls} />
    case 'model_server':        return <Cpu className={cls} />
    case 'llm_api_endpoint':    return <Cloud className={cls} />
    case 'cloud_ai_service':    return <Database className={cls} />
    case 'k8s_deployment':      return <Layers className={cls} />
    case 'k8s_service':         return <GitBranch className={cls} />
    default:                    return <Server className={cls} />
  }
}

const TYPE_LABEL: Record<string, string> = {
  mcp_server:         'MCP Server',
  agentic_framework:  'Agent',
  model_server:       'Model Server',
  llm_api_endpoint:   'LLM Endpoint',
  cloud_ai_service:   'AI Service',
  k8s_deployment:     'Deployment',
  k8s_service:        'Service',
}

function AssetNode({ data, selected }: NodeProps<AssetNodeData>) {
  const name     = data.label ?? 'Unknown'
  const display  = name.length > 22 ? name.slice(0, 22) + '…' : name
  const level    = riskLevel(data.risk_score)
  const ringCls  = RISK_RING[level]
  const badgeCls = PROVIDER_BADGE[data.provider] ?? 'bg-slate-700/50 text-slate-400'
  const typeLabel = TYPE_LABEL[data.asset_type] ?? data.asset_type?.replace('_', ' ')

  return (
    <div
      className={clsx(
        'rounded-lg px-3 py-2.5 w-[200px] shadow-lg border transition-all',
        'bg-[#13151f]',
        selected
          ? 'border-specter-accent shadow-specter-accent/30 shadow-md'
          : 'border-[#252836] hover:border-[#3a3d52]'
      )}
    >
      <Handle type="target" position={Position.Top}    className="!bg-specter-accent/60 !border-specter-border !w-1.5 !h-1.5" />
      <Handle type="source" position={Position.Bottom} className="!bg-specter-accent/60 !border-specter-border !w-1.5 !h-1.5" />

      <div className="flex items-start gap-2">
        {/* Icon + type */}
        <div className="flex flex-col items-center gap-1 shrink-0 mt-0.5">
          <div className="text-slate-400">
            <AssetIcon type={data.asset_type} />
          </div>
        </div>

        {/* Name + subtitle */}
        <div className="flex-1 min-w-0">
          <p className="text-white text-xs font-semibold leading-tight truncate" title={name}>
            {display}
          </p>
          <p className="text-slate-500 text-[10px] mt-0.5 truncate">
            {typeLabel}
            {data.namespace ? ` · ${data.namespace}` : ''}
          </p>
        </div>

        {/* Risk score badge */}
        {data.risk_score != null && (
          <div className={clsx('shrink-0 flex items-center justify-center w-6 h-6 rounded-full text-[10px] font-bold', ringCls)}>
            {Math.round(data.risk_score)}
          </div>
        )}
      </div>

      {/* Provider tag */}
      <div className="mt-2 pt-2 border-t border-[#1e2030] flex items-center justify-between">
        <span className={clsx('inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium', badgeCls)}>
          {data.provider}
        </span>
        {data.cluster && (
          <span className="text-[10px] text-slate-600 truncate max-w-[90px]" title={data.cluster}>
            {data.cluster}
          </span>
        )}
      </div>
    </div>
  )
}

export default memo(AssetNode)
