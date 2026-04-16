import { NavLink } from 'react-router-dom'
import {
  Shield,
  LayoutDashboard,
  Package,
  AlertTriangle,
  ShieldAlert,
  Network,
  Settings,
} from 'lucide-react'
import { clsx } from 'clsx'

const navItems = [
  { to: '/',                icon: LayoutDashboard, label: 'Dashboard',       exact: true },
  { to: '/inventory',       icon: Package,          label: 'Inventory' },
  { to: '/threats',         icon: AlertTriangle,    label: 'Threats' },
  { to: '/vulnerabilities', icon: ShieldAlert,      label: 'Vulnerabilities' },
  { to: '/graph',           icon: Network,          label: 'Map' },
  { to: '/settings',        icon: Settings,         label: 'Settings' },
]

export default function Sidebar() {
  return (
    <aside className="flex flex-col w-56 shrink-0 bg-specter-surface border-r border-specter-border min-h-screen">
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-5 py-5 border-b border-specter-border">
        <div className="flex items-center justify-center w-8 h-8 bg-specter-accent/20 rounded-lg">
          <Shield size={18} className="text-specter-accent" />
        </div>
        <span className="text-white font-semibold tracking-wide text-base">Specter</span>
        <span className="ml-auto text-[10px] text-slate-500 font-mono bg-specter-border px-1.5 py-0.5 rounded">AI SEC</span>
      </div>

      {/* Nav */}
      <nav className="flex flex-col gap-0.5 p-3 flex-1">
        {navItems.map(({ to, icon: Icon, label, exact }) => (
          <NavLink
            key={to}
            to={to}
            end={exact}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded text-sm font-medium transition-colors',
                isActive
                  ? 'bg-specter-accent/15 text-specter-accent border border-specter-accent/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-specter-border/60'
              )
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-specter-border">
        <p className="text-[11px] text-slate-600">Specter v0.1.0</p>
      </div>
    </aside>
  )
}
