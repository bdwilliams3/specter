import { useEffect, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Loader2 } from 'lucide-react'

interface AuthGuardProps {
  children: ReactNode
}

type AuthState = 'checking' | 'authenticated' | 'unauthenticated' | 'dev'

export default function AuthGuard({ children }: AuthGuardProps) {
  const [authState, setAuthState] = useState<AuthState>('checking')
  const navigate = useNavigate()

  useEffect(() => {
    const token = localStorage.getItem('specter_token')

    // In dev mode with bypass token, allow through
    if (token === 'dev-token') {
      setAuthState('dev')
      return
    }

    if (!token) {
      // Try to discover if OIDC is configured
      fetch('/auth/me', { headers: { 'Accept': 'application/json' } })
        .then(r => {
          if (r.ok) {
            // OIDC is configured but we have no token — redirect to login
            setAuthState('unauthenticated')
          } else if (r.status === 401) {
            setAuthState('unauthenticated')
          } else {
            // Backend not available or OIDC not configured — allow dev access
            setAuthState('dev')
          }
        })
        .catch(() => {
          // No backend — allow through in dev mode
          setAuthState('dev')
        })
      return
    }

    // Validate existing token
    fetch('/auth/me', {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
    })
      .then(r => {
        if (r.ok) {
          setAuthState('authenticated')
        } else if (r.status === 401) {
          localStorage.removeItem('specter_token')
          setAuthState('unauthenticated')
        } else {
          // Other errors — assume ok for resilience
          setAuthState('authenticated')
        }
      })
      .catch(() => {
        // Backend unavailable — allow through
        setAuthState(token ? 'authenticated' : 'dev')
      })
  }, [])

  useEffect(() => {
    if (authState === 'unauthenticated') {
      navigate('/login', { replace: true })
    }
  }, [authState, navigate])

  if (authState === 'checking') {
    return (
      <div className="min-h-screen bg-specter-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="flex items-center justify-center w-12 h-12 bg-specter-accent/20 rounded-xl">
            <Shield size={22} className="text-specter-accent" />
          </div>
          <div className="flex items-center gap-2 text-sm text-slate-400">
            <Loader2 size={14} className="animate-spin" />
            Checking authentication…
          </div>
        </div>
      </div>
    )
  }

  if (authState === 'unauthenticated') {
    return null // navigate() will take over
  }

  return <>{children}</>
}
