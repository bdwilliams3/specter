import { useEffect, useState } from 'react'
import { Shield, Loader2, AlertCircle } from 'lucide-react'

export default function Login() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Handle OIDC callback — if we're on the callback URL, parse state from query params
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const errorParam = params.get('error')

    if (errorParam) {
      setError(`Authentication failed: ${params.get('error_description') ?? errorParam}`)
      return
    }

    if (code) {
      setLoading(true)
      // Exchange code for token via backend
      fetch(`/auth/callback${window.location.search}`)
        .then(r => r.json())
        .then(data => {
          if (data.token) {
            localStorage.setItem('specter_token', data.token)
            window.location.href = '/'
          } else {
            setError('Authentication failed: no token received.')
            setLoading(false)
          }
        })
        .catch(() => {
          setError('Authentication failed: could not reach server.')
          setLoading(false)
        })
    }
  }, [])

  const handleSSO = () => {
    setLoading(true)
    setError(null)
    window.location.href = '/auth/login'
  }

  const handleDevBypass = () => {
    localStorage.setItem('specter_token', 'dev-token')
    window.location.href = '/'
  }

  return (
    <div className="min-h-screen bg-specter-bg flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="flex items-center justify-center w-16 h-16 bg-specter-accent/20 border border-specter-accent/30 rounded-2xl mb-4">
            <Shield size={32} className="text-specter-accent" />
          </div>
          <h1 className="text-2xl font-bold text-white">Specter</h1>
          <p className="text-slate-400 text-sm mt-1">AI Security Monitoring Platform</p>
        </div>

        {/* Login card */}
        <div className="bg-specter-surface border border-specter-border rounded-xl p-6 flex flex-col gap-4">
          <div>
            <h2 className="text-white font-semibold text-base">Sign in to your workspace</h2>
            <p className="text-slate-400 text-sm mt-1">Use your organization's SSO provider to authenticate.</p>
          </div>

          {error && (
            <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded text-sm text-red-400">
              <AlertCircle size={15} className="shrink-0 mt-0.5" />
              {error}
            </div>
          )}

          <button
            onClick={handleSSO}
            disabled={loading}
            className="flex items-center justify-center gap-2 w-full py-2.5 text-sm font-semibold bg-specter-accent hover:bg-specter-accent-hover text-white rounded-lg disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                Redirecting…
              </>
            ) : (
              'Sign in with SSO'
            )}
          </button>

          {/* Dev bypass — only visible in dev mode */}
          {import.meta.env.DEV && (
            <button
              onClick={handleDevBypass}
              className="w-full py-2 text-xs text-slate-500 hover:text-slate-300 transition-colors border border-dashed border-specter-border rounded hover:border-slate-600"
            >
              Skip auth (dev mode)
            </button>
          )}
        </div>

        <p className="text-center text-xs text-slate-600 mt-6">
          Specter &copy; {new Date().getFullYear()} — All rights reserved
        </p>
      </div>
    </div>
  )
}
