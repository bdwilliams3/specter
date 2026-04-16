import { useEffect, useState, useRef } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'
import { Package, AlertTriangle, Clock } from 'lucide-react'
import { getMetrics } from '../api/metrics'
import { getThreats } from '../api/threats'
import SeverityBadge from '../components/shared/SeverityBadge'

interface Metrics {
  total_assets: number
  total_threats: number
  total_vulnerabilities: number
  last_scan?: { id: string; scanner: string; status: string; started_at: string } | null
  threats_by_severity?: Record<string, number>
  vulnerabilities_by_severity?: Record<string, number>
  assets_by_provider?: Record<string, number>
}

interface Threat {
  event_id: string
  threat_name: string
  severity: string
  category?: string
  detected_at?: string
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#3b82f6',
}

const PROVIDER_COLORS = ['#6366f1', '#22c55e', '#f97316', '#3b82f6', '#a855f7', '#ec4899']

function StatCard({ label, value, icon: Icon, color }: { label: string; value: string | number; icon: React.ElementType; color: string }) {
  return (
    <div className="bg-specter-surface border border-specter-border rounded-lg p-5 flex items-center gap-4">
      <div className={`flex items-center justify-center w-12 h-12 rounded-lg ${color}`}>
        <Icon size={22} />
      </div>
      <div>
        <p className="text-2xl font-bold text-white">{value}</p>
        <p className="text-sm text-slate-400 mt-0.5">{label}</p>
      </div>
    </div>
  )
}

function formatScan(ts?: string) {
  if (!ts) return 'Never'
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return ts
  }
}

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [threats, setThreats] = useState<Threat[]>([])
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    getMetrics().then(setMetrics).catch(() => {})
    getThreats({ limit: 10, sort: 'desc' }).then(r => setThreats(Array.isArray(r) ? r : r.items ?? [])).catch(() => {})
  }, [])

  // Live threat feed via WS
  useEffect(() => {
    let reconnectTimer: ReturnType<typeof setTimeout>

    const connect = () => {
      try {
        const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/events`)
        wsRef.current = ws
        ws.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data)
            if (data.type === 'threat') {
              setThreats(prev => [data, ...prev].slice(0, 10))
            }
          } catch {}
        }
        ws.onclose = () => { reconnectTimer = setTimeout(connect, 5000) }
        ws.onerror = () => ws.close()
      } catch {
        reconnectTimer = setTimeout(connect, 5000)
      }
    }
    connect()
    return () => { clearTimeout(reconnectTimer); wsRef.current?.close() }
  }, [])

  const vulnChartData = metrics?.vulnerabilities_by_severity
    ? Object.entries(metrics.vulnerabilities_by_severity)
        .filter(([, v]) => v > 0)
        .map(([k, v]) => ({ name: k, value: v, fill: SEVERITY_COLORS[k] ?? '#6366f1' }))
    : []

  const providerChartData = metrics?.assets_by_provider
    ? Object.entries(metrics.assets_by_provider).map(([k, v], i) => ({ name: k, value: v, fill: PROVIDER_COLORS[i % PROVIDER_COLORS.length] }))
    : []

  return (
    <div className="flex flex-col gap-6">
      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Total Assets"   value={metrics?.total_assets ?? '—'}  icon={Package}       color="bg-indigo-500/20 text-indigo-400" />
        <StatCard label="Active Threats" value={metrics?.total_threats ?? '—'} icon={AlertTriangle} color="bg-orange-500/20 text-orange-400" />
        <StatCard label="Last Scan"      value={formatScan(metrics?.last_scan?.started_at)} icon={Clock} color="bg-green-500/20 text-green-400" />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Vulnerabilities by Severity — replaces stat card */}
        <div className="bg-specter-surface border border-specter-border rounded-lg p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Open Vulnerabilities</h2>
            <span className="text-2xl font-bold text-white">{metrics?.total_vulnerabilities ?? '—'}</span>
          </div>
          {vulnChartData.length === 0 ? (
            <div className="flex items-center justify-center h-36 text-slate-500 text-sm">No vulnerabilities</div>
          ) : (
            <ResponsiveContainer width="100%" height={150}>
              <BarChart data={vulnChartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: '#1a1d27', border: '1px solid #2a2d3e', borderRadius: 6 }}
                  labelStyle={{ color: '#e2e8f0' }}
                  itemStyle={{ color: '#94a3b8' }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {vulnChartData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="bg-specter-surface border border-specter-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wider">Assets by Provider</h2>
          {providerChartData.length === 0 ? (
            <div className="flex items-center justify-center h-36 text-slate-500 text-sm">No data</div>
          ) : (
            <ResponsiveContainer width="100%" height={150}>
              <PieChart>
                <Pie data={providerChartData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={55} innerRadius={28}>
                  {providerChartData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Legend iconType="circle" iconSize={10} formatter={(v) => <span style={{ color: '#94a3b8', fontSize: 12 }}>{v}</span>} />
                <Tooltip
                  contentStyle={{ background: '#1a1d27', border: '1px solid #2a2d3e', borderRadius: 6 }}
                  labelStyle={{ color: '#e2e8f0' }}
                  itemStyle={{ color: '#94a3b8' }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Recent threats */}
      <div className="bg-specter-surface border border-specter-border rounded-lg p-5">
        <h2 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wider flex items-center gap-2">
          Recent Threats
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
          </span>
          <span className="text-xs text-slate-500 font-normal normal-case ml-1">live</span>
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-specter-border">
                <th className="text-left text-xs text-slate-500 font-medium uppercase tracking-wider pb-2 pr-4">Title</th>
                <th className="text-left text-xs text-slate-500 font-medium uppercase tracking-wider pb-2 pr-4">Severity</th>
                <th className="text-left text-xs text-slate-500 font-medium uppercase tracking-wider pb-2 pr-4">Category</th>
                <th className="text-left text-xs text-slate-500 font-medium uppercase tracking-wider pb-2">Detected</th>
              </tr>
            </thead>
            <tbody>
              {threats.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-500">No recent threats</td>
                </tr>
              ) : threats.map((t) => (
                <tr key={t.event_id} className="border-b border-specter-border/40 hover:bg-specter-border/20 transition-colors">
                  <td className="py-2.5 pr-4 text-slate-200 font-medium">{t.threat_name}</td>
                  <td className="py-2.5 pr-4"><SeverityBadge severity={t.severity} /></td>
                  <td className="py-2.5 pr-4 text-slate-400">{t.category ?? '—'}</td>
                  <td className="py-2.5 text-slate-500 text-xs">
                    {t.detected_at ? new Date(t.detected_at).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
