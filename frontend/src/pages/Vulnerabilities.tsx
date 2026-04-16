import { useEffect, useState, useCallback } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { X, CheckCircle } from 'lucide-react'
import { getVulns } from '../api/vulnerabilities'
import DataTable from '../components/shared/DataTable'
import SeverityBadge from '../components/shared/SeverityBadge'
import ExportMenu from '../components/shared/ExportMenu'

interface Vuln {
  id: string
  title: string
  severity: string
  category?: string
  cvss_score?: number
  first_seen?: string
  description?: string
  remediation?: string | string[]
  cve_id?: string
  asset_id?: string
  asset_name?: string
  cluster?: string
  scanner_name?: string
}

const PAGE_SIZE = 20

export default function Vulnerabilities() {
  const [vulns, setVulns]       = useState<Vuln[]>([])
  const [total, setTotal]       = useState(0)
  const [page, setPage]         = useState(1)
  const [isLoading, setIsLoading] = useState(false)
  const [selected, setSelected] = useState<Vuln | null>(null)

  const fetchVulns = useCallback(async () => {
    setIsLoading(true)
    try {
      const data = await getVulns({ page, page_size: PAGE_SIZE })
      const items = Array.isArray(data) ? data : data.items ?? []
      setVulns(items)
      setTotal(Array.isArray(data) ? data.length : data.total ?? items.length)
    } catch {
      setVulns([])
    } finally {
      setIsLoading(false)
    }
  }, [page])

  useEffect(() => { fetchVulns() }, [fetchVulns])

  const columns: ColumnDef<Vuln, unknown>[] = [
    {
      accessorKey: 'title',
      header: 'Title',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => <span className="text-white font-medium">{info.getValue() as string}</span>
    },
    {
      accessorKey: 'severity',
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
      accessorKey: 'cvss_score',
      header: 'CVSS',
      enableSorting: true,
      enableColumnFilter: false,
      cell: info => {
        const v = info.getValue() as number | undefined
        if (v == null) return <span className="text-slate-500">—</span>
        const color = v >= 9 ? 'text-red-400' : v >= 7 ? 'text-orange-400' : v >= 4 ? 'text-yellow-400' : 'text-green-400'
        return <span className={`font-mono font-semibold ${color}`}>{v.toFixed(1)}</span>
      }
    },
    {
      accessorKey: 'cluster',
      header: 'Host',
      enableSorting: true,
      enableColumnFilter: true,
      filterFn: 'multiSelect',
      cell: info => {
        const row = info.row.original
        const cluster = row.cluster || row.scanner_name || '—'
        return <span className="text-slate-300 font-mono text-xs">{cluster}</span>
      }
    },
    {
      accessorKey: 'first_seen',
      header: 'First Seen',
      enableSorting: true,
      enableColumnFilter: false,
      cell: info => {
        const v = info.getValue() as string | undefined
        return <span className="text-slate-400 text-xs">{v ? new Date(v).toLocaleString() : '—'}</span>
      }
    },
  ]

  const remediationSteps = selected?.remediation
    ? (Array.isArray(selected.remediation) ? selected.remediation : [selected.remediation])
    : []

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-end">
        <ExportMenu entity="vulnerabilities" />
      </div>

      <DataTable
        columns={columns}
        data={vulns}
        isLoading={isLoading}
        onRowClick={setSelected}
        pagination={{ page, pageSize: PAGE_SIZE, total, onPageChange: setPage }}
      />

      {selected && (
        <div className="fixed inset-0 z-40 flex justify-end">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setSelected(null)} />
          <div className="relative z-10 w-full max-w-lg bg-specter-surface border-l border-specter-border shadow-2xl flex flex-col overflow-y-auto">
            <div className="flex items-center justify-between px-6 py-4 border-b border-specter-border sticky top-0 bg-specter-surface z-10">
              <div className="flex items-center gap-3">
                <h2 className="text-white font-semibold text-base">Vulnerability Detail</h2>
                <SeverityBadge severity={selected.severity} />
              </div>
              <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-white transition-colors">
                <X size={18} />
              </button>
            </div>
            <div className="flex-1 px-6 py-5 flex flex-col gap-5">
              <div>
                <h3 className="text-xl font-bold text-white">{selected.title}</h3>
                {selected.cve_id && (
                  <span className="inline-block mt-1.5 px-2 py-0.5 text-xs font-mono font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/20 rounded">
                    {selected.cve_id}
                  </span>
                )}
                <p className="text-slate-400 text-sm mt-2 leading-relaxed">{selected.description ?? 'No description available.'}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: 'Category',   value: selected.category ?? '—' },
                  { label: 'CVSS Score', value: selected.cvss_score != null ? selected.cvss_score.toFixed(1) : '—' },
                  { label: 'Host',       value: selected.cluster ?? selected.scanner_name ?? '—' },
                  { label: 'Asset',      value: selected.asset_name ?? selected.asset_id ?? '—' },
                  { label: 'First Seen', value: selected.first_seen ? new Date(selected.first_seen).toLocaleString() : '—' },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</p>
                    <p className="text-sm text-slate-200 font-medium font-mono">{value}</p>
                  </div>
                ))}
              </div>

              {remediationSteps.length > 0 && (
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-3">Remediation Steps</p>
                  <div className="flex flex-col gap-2">
                    {remediationSteps.map((step, i) => (
                      <div key={i} className="flex items-start gap-3 p-3 bg-green-500/5 border border-green-500/20 rounded">
                        <CheckCircle size={15} className="shrink-0 text-green-400 mt-0.5" />
                        <p className="text-sm text-slate-300 leading-relaxed">{step}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
