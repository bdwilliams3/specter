import { useEffect, useState } from 'react'
import { CheckCircle, XCircle, Loader2, ToggleLeft, ToggleRight, Activity } from 'lucide-react'
import { getScanners } from '../api/scans'
import { testIntegration } from '../api/integrations'

interface Scanner {
  name: string
  description?: string
  enabled?: boolean
  version?: string
}

type TestStatus = 'idle' | 'testing' | 'ok' | 'failed'

const INTEGRATIONS = [
  {
    name: 'splunk',
    label: 'Splunk',
    description: 'Forward security events and alerts to Splunk SIEM for correlation and analysis.',
    logo: '🔴',
  },
  {
    name: 'cribl',
    label: 'Cribl Stream',
    description: 'Route and transform security telemetry through Cribl for observability pipelines.',
    logo: '🟠',
  },
  {
    name: 'grafana',
    label: 'Grafana',
    description: 'Visualize Specter metrics and alerts in Grafana dashboards with Prometheus datasource.',
    logo: '🟡',
  },
]

export default function Settings() {
  const [scanners, setScanners] = useState<Scanner[]>([])
  const [enabled, setEnabled] = useState<Record<string, boolean>>({})
  const [integrationStatus, setIntegrationStatus] = useState<Record<string, TestStatus>>({})

  useEffect(() => {
    getScanners()
      .then(data => {
        const list: Scanner[] = Array.isArray(data) ? data : data.scanners ?? []
        setScanners(list)
        const defaults: Record<string, boolean> = {}
        list.forEach(s => { defaults[s.name] = s.enabled ?? true })
        setEnabled(defaults)
      })
      .catch(() => {
        // Show fallback scanners when backend is unavailable
        const fallback: Scanner[] = [
          { name: 'nuclei',   description: 'Fast HTTP-based vulnerability scanner',         enabled: true,  version: 'v3.x' },
          { name: 'trivy',    description: 'Container image & filesystem vulnerability scan', enabled: true,  version: 'v0.50.x' },
          { name: 'grype',    description: 'Vulnerability scanner for container images',      enabled: false, version: 'v0.76.x' },
          { name: 'semgrep',  description: 'Static analysis for code security',              enabled: true,  version: 'v1.x' },
          { name: 'gitleaks', description: 'Detect secrets in git repositories',             enabled: false, version: 'v8.x' },
        ]
        setScanners(fallback)
        const defaults: Record<string, boolean> = {}
        fallback.forEach(s => { defaults[s.name] = s.enabled ?? true })
        setEnabled(defaults)
      })
  }, [])

  const testConnection = async (name: string) => {
    setIntegrationStatus(s => ({ ...s, [name]: 'testing' }))
    try {
      await testIntegration(name)
      setIntegrationStatus(s => ({ ...s, [name]: 'ok' }))
    } catch {
      setIntegrationStatus(s => ({ ...s, [name]: 'failed' }))
    }
    setTimeout(() => {
      setIntegrationStatus(s => ({ ...s, [name]: 'idle' }))
    }, 4000)
  }

  return (
    <div className="flex flex-col gap-8 max-w-3xl">
      {/* Scanners section */}
      <section>
        <div className="mb-4">
          <h2 className="text-white font-semibold text-base">Scanners</h2>
          <p className="text-slate-400 text-sm mt-1">Manage which security scanners are available for scan jobs.</p>
        </div>
        <div className="flex flex-col gap-3">
          {scanners.length === 0
            ? Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-16 bg-specter-surface border border-specter-border rounded-lg animate-pulse" />
            ))
            : scanners.map(scanner => (
              <div
                key={scanner.name}
                className="flex items-center justify-between gap-4 bg-specter-surface border border-specter-border rounded-lg px-5 py-4 hover:border-specter-accent/40 transition-colors"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-white font-medium capitalize">{scanner.name}</p>
                    {scanner.version && (
                      <span className="text-[10px] text-slate-500 font-mono bg-specter-border px-1.5 py-0.5 rounded">{scanner.version}</span>
                    )}
                  </div>
                  {scanner.description && (
                    <p className="text-slate-400 text-xs mt-0.5">{scanner.description}</p>
                  )}
                </div>
                <button
                  onClick={() => setEnabled(e => ({ ...e, [scanner.name]: !e[scanner.name] }))}
                  className={`flex items-center gap-1.5 text-sm font-medium transition-colors ${enabled[scanner.name] ? 'text-specter-accent' : 'text-slate-500'}`}
                  title={enabled[scanner.name] ? 'Disable' : 'Enable'}
                >
                  {enabled[scanner.name]
                    ? <ToggleRight size={28} className="text-specter-accent" />
                    : <ToggleLeft size={28} className="text-slate-600" />}
                </button>
              </div>
            ))}
        </div>
      </section>

      {/* Observability integrations section */}
      <section>
        <div className="mb-4">
          <h2 className="text-white font-semibold text-base">Observability Integrations</h2>
          <p className="text-slate-400 text-sm mt-1">Test connectivity to your observability and SIEM platforms.</p>
        </div>
        <div className="grid grid-cols-1 gap-4">
          {INTEGRATIONS.map(intg => {
            const status = integrationStatus[intg.name] ?? 'idle'
            return (
              <div
                key={intg.name}
                className="flex items-center gap-5 bg-specter-surface border border-specter-border rounded-lg px-5 py-4"
              >
                <div className="text-2xl w-10 text-center">{intg.logo}</div>
                <div className="flex-1 min-w-0">
                  <p className="text-white font-medium">{intg.label}</p>
                  <p className="text-slate-400 text-xs mt-0.5 leading-relaxed">{intg.description}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  {status === 'ok' && (
                    <span className="flex items-center gap-1 text-xs text-green-400">
                      <CheckCircle size={14} /> Connected
                    </span>
                  )}
                  {status === 'failed' && (
                    <span className="flex items-center gap-1 text-xs text-red-400">
                      <XCircle size={14} /> Failed
                    </span>
                  )}
                  <button
                    onClick={() => testConnection(intg.name)}
                    disabled={status === 'testing'}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-specter-border text-slate-300 rounded hover:border-specter-accent hover:text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {status === 'testing' ? (
                      <>
                        <Loader2 size={12} className="animate-spin" />
                        Testing…
                      </>
                    ) : (
                      <>
                        <Activity size={12} />
                        Test Connection
                      </>
                    )}
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      </section>
    </div>
  )
}
