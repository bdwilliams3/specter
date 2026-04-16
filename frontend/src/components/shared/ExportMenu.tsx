import { useState, useRef, useEffect } from 'react'
import { Download, ChevronDown } from 'lucide-react'
import { exportReport } from '../../api/reports'

interface ExportMenuProps {
  entity: string
}

const formats = [
  { key: 'csv',  label: 'Export as CSV' },
  { key: 'json', label: 'Export as JSON' },
  { key: 'html', label: 'Export as HTML' },
]

export default function ExportMenu({ entity }: ExportMenuProps) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState<string | null>(null)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const handleExport = async (format: string) => {
    setLoading(format)
    setOpen(false)
    try {
      const blob = await exportReport(format, entity)
      const ext = format === 'html' ? 'html' : format === 'json' ? 'json' : 'csv'
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `specter-${entity}-${Date.now()}.${ext}`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // silently fail in UI — backend may not be available
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-specter-surface border border-specter-border text-slate-300 rounded hover:border-specter-accent hover:text-white transition-colors"
      >
        <Download size={14} />
        {loading ? 'Exporting…' : 'Export'}
        <ChevronDown size={12} className={open ? 'rotate-180 transition-transform' : 'transition-transform'} />
      </button>
      {open && (
        <div className="absolute right-0 mt-1 z-50 w-44 bg-specter-surface border border-specter-border rounded shadow-xl py-1">
          {formats.map(f => (
            <button
              key={f.key}
              onClick={() => handleExport(f.key)}
              className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:bg-specter-border hover:text-white transition-colors"
            >
              {f.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
