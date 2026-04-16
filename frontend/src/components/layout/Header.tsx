import { useState } from 'react'
import { Scan, X, Loader2 } from 'lucide-react'
import { triggerScan } from '../../api/scans'

interface HeaderProps {
  title: string
}

export default function Header({ title }: HeaderProps) {
  const [modalOpen, setModalOpen] = useState(false)
  const [scanner, setScanner] = useState('nuclei')
  const [target, setTarget] = useState('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<string | null>(null)

  const handleTrigger = async () => {
    if (!target.trim()) return
    setRunning(true)
    setResult(null)
    try {
      await triggerScan(scanner, target)
      setResult('Scan triggered successfully.')
    } catch {
      setResult('Failed to trigger scan. Check backend connection.')
    } finally {
      setRunning(false)
    }
  }

  const handleClose = () => {
    setModalOpen(false)
    setResult(null)
    setTarget('')
  }

  return (
    <>
      <header className="flex items-center justify-between px-6 py-4 border-b border-specter-border bg-specter-bg/80 backdrop-blur sticky top-0 z-30">
        <h1 className="text-lg font-semibold text-white">{title}</h1>
        <button
          onClick={() => setModalOpen(true)}
          className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium bg-specter-accent hover:bg-specter-accent-hover text-white rounded transition-colors"
        >
          <Scan size={14} />
          Trigger Scan
        </button>
      </header>

      {/* Modal overlay */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-specter-surface border border-specter-border rounded-xl shadow-2xl w-full max-w-md p-6">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-white font-semibold text-base">Trigger Security Scan</h2>
              <button onClick={handleClose} className="text-slate-400 hover:text-white transition-colors">
                <X size={18} />
              </button>
            </div>

            <div className="flex flex-col gap-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1.5 font-medium uppercase tracking-wider">Scanner</label>
                <select
                  value={scanner}
                  onChange={e => setScanner(e.target.value)}
                  className="w-full bg-specter-bg border border-specter-border text-slate-200 rounded px-3 py-2 text-sm focus:outline-none focus:border-specter-accent"
                >
                  <option value="nuclei">Nuclei</option>
                  <option value="trivy">Trivy</option>
                  <option value="grype">Grype</option>
                  <option value="semgrep">Semgrep</option>
                  <option value="gitleaks">Gitleaks</option>
                </select>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1.5 font-medium uppercase tracking-wider">Target</label>
                <input
                  type="text"
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  placeholder="e.g. https://api.example.com or image:tag"
                  className="w-full bg-specter-bg border border-specter-border text-slate-200 rounded px-3 py-2 text-sm placeholder:text-slate-600 focus:outline-none focus:border-specter-accent"
                />
              </div>

              {result && (
                <p className={`text-sm px-3 py-2 rounded border ${result.includes('success') ? 'bg-green-500/10 border-green-500/30 text-green-400' : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
                  {result}
                </p>
              )}

              <div className="flex justify-end gap-2 mt-1">
                <button
                  onClick={handleClose}
                  className="px-4 py-2 text-sm text-slate-400 hover:text-white hover:bg-specter-border rounded transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleTrigger}
                  disabled={running || !target.trim()}
                  className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-specter-accent hover:bg-specter-accent-hover text-white rounded disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {running && <Loader2 size={14} className="animate-spin" />}
                  {running ? 'Running…' : 'Run Scan'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
