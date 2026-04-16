import { useEffect, useState, useRef } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { AlertTriangle, ShieldAlert, X } from 'lucide-react'
import Sidebar from './Sidebar'
import Header from './Header'

interface WsEvent {
  type: 'threat' | 'vulnerability'
  title: string
  severity: string
  id: string
}

interface Toast {
  id: number
  event: WsEvent
}

const PAGE_TITLES: Record<string, string> = {
  '/':                          'Dashboard',
  '/inventory':                 'AI Asset Inventory',
  '/threats':                   'Threat Events',
  '/posture/vulnerabilities':   'Vulnerabilities',
  '/posture/policies':          'Policies',
  '/graph':                     'Topology Map',
  '/settings':                  'Settings',
}

let toastId = 0

export default function Layout() {
  const location = useLocation()
  const [toasts, setToasts] = useState<Toast[]>([])
  const wsRef = useRef<WebSocket | null>(null)

  const title = PAGE_TITLES[location.pathname] ?? 'Specter'

  useEffect(() => {
    let reconnectTimer: ReturnType<typeof setTimeout>

    const connect = () => {
      try {
        const ws = new WebSocket(`${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/events`)
        wsRef.current = ws

        ws.onmessage = (e) => {
          try {
            const data: WsEvent = JSON.parse(e.data)
            if (data.type === 'threat' || data.type === 'vulnerability') {
              const id = ++toastId
              setToasts(prev => [...prev, { id, event: data }])
              setTimeout(() => {
                setToasts(prev => prev.filter(t => t.id !== id))
              }, 6000)
            }
          } catch {
            // ignore malformed messages
          }
        }

        ws.onclose = () => {
          reconnectTimer = setTimeout(connect, 5000)
        }

        ws.onerror = () => {
          ws.close()
        }
      } catch {
        reconnectTimer = setTimeout(connect, 5000)
      }
    }

    connect()

    return () => {
      clearTimeout(reconnectTimer)
      wsRef.current?.close()
    }
  }, [])

  const dismissToast = (id: number) => setToasts(prev => prev.filter(t => t.id !== id))

  return (
    <div className="flex min-h-screen bg-specter-bg">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0">
        <Header title={title} />
        <main className="flex-1 p-6 overflow-auto">
          <Outlet />
        </main>
      </div>

      {/* Toast notifications */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
        {toasts.map(toast => (
          <div
            key={toast.id}
            className="pointer-events-auto flex items-start gap-3 bg-specter-surface border border-specter-border rounded-lg p-4 shadow-xl animate-in slide-in-from-right"
          >
            <div className={`shrink-0 mt-0.5 ${toast.event.type === 'threat' ? 'text-orange-400' : 'text-yellow-400'}`}>
              {toast.event.type === 'threat' ? <AlertTriangle size={16} /> : <ShieldAlert size={16} />}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-0.5">
                New {toast.event.type === 'threat' ? 'Threat' : 'Vulnerability'}
              </p>
              <p className="text-sm text-white truncate">{toast.event.title}</p>
              {toast.event.severity && (
                <p className="text-xs text-slate-400 mt-0.5 capitalize">{toast.event.severity} severity</p>
              )}
            </div>
            <button
              onClick={() => dismissToast(toast.id)}
              className="shrink-0 text-slate-500 hover:text-slate-300 transition-colors"
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
