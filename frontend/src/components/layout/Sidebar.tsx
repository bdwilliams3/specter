import { NavLink, useLocation } from 'react-router-dom'
import {
  Shield,
  LayoutDashboard,
  Package,
  AlertTriangle,
  ShieldAlert,
  Network,
  Settings,
  BookOpen,
  ChevronDown,
  ChevronRight,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useState } from 'react'

const topNavItems = [
  { to: '/',         icon: LayoutDashboard, label: 'Dashboard',  exact: true },
  { to: '/inventory', icon: Package,         label: 'Inventory' },
  { to: '/threats',   icon: AlertTriangle,   label: 'Threats' },
]

const postureItems = [
  { to: '/posture/vulnerabilities', icon: ShieldAlert, label: 'Vulnerabilities' },
  { to: '/posture/policies',        icon: BookOpen,    label: 'Policies' },
]

const bottomNavItems = [
  { to: '/graph',    icon: Network,  label: 'Map' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

function NavItem({ to, icon: Icon, label, exact }: { to: string; icon: React.ElementType; label: string; exact?: boolean }) {
  return (
    <NavLink
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
  )
}

function SubNavItem({ to, icon: Icon, label }: { to: string; icon: React.ElementType; label: string }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        clsx(
          'flex items-center gap-3 pl-7 pr-3 py-2 rounded text-sm font-medium transition-colors',
          isActive
            ? 'bg-specter-accent/15 text-specter-accent border border-specter-accent/20'
            : 'text-slate-400 hover:text-slate-200 hover:bg-specter-border/60'
        )
      }
    >
      <Icon size={14} />
      {label}
    </NavLink>
  )
}

export default function Sidebar() {
  const location = useLocation()
  const inPosture = location.pathname.startsWith('/posture')
  const [postureOpen, setPostureOpen] = useState(inPosture)

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
        {topNavItems.map(({ to, icon, label, exact }) => (
          <NavItem key={to} to={to} icon={icon} label={label} exact={exact} />
        ))}

        {/* Posture Management group */}
        <div className="mt-1">
          <button
            onClick={() => setPostureOpen(o => !o)}
            className={clsx(
              'w-full flex items-center gap-3 px-3 py-2.5 rounded text-sm font-medium transition-colors',
              inPosture
                ? 'text-specter-accent'
                : 'text-slate-400 hover:text-slate-200 hover:bg-specter-border/60'
            )}
          >
            <ShieldAlert size={16} />
            <span className="flex-1 text-left">Posture Management</span>
            {postureOpen
              ? <ChevronDown size={13} className="text-slate-500" />
              : <ChevronRight size={13} className="text-slate-500" />
            }
          </button>
          {postureOpen && (
            <div className="flex flex-col gap-0.5 mt-0.5">
              {postureItems.map(({ to, icon, label }) => (
                <SubNavItem key={to} to={to} icon={icon} label={label} />
              ))}
            </div>
          )}
        </div>

        {bottomNavItems.map(({ to, icon, label }) => (
          <NavItem key={to} to={to} icon={icon} label={label} />
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-specter-border">
        <p className="text-[11px] text-slate-600">Specter v0.1.0</p>
      </div>
    </aside>
  )
}
