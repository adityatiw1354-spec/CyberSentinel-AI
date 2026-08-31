import {
  LayoutDashboard,
  ScanSearch,
  KeyRound,
  History,
  UserRound,
  Settings,
  ShieldCheck,
  Code2,
} from 'lucide-react'
import { NavLink } from 'react-router-dom'

const navigation = [
  {
    name: 'Dashboard',
    path: '/dashboard',
    icon: LayoutDashboard,
  },
  {
    name: 'URL Scanner',
    path: '/url-scanner',
    icon: ScanSearch,
  },
  {
    name: 'Password Analyzer',
    path: '/password-analyzer',
    icon: KeyRound,
  },
  {
    name: 'Scan History',
    path: '/scan-history',
    icon: History,
  },
]

const secondaryNavigation = [
  {
    name: 'Profile',
    path: '/profile',
    icon: UserRound,
  },
  {
    name: 'Creator',
    path: '/creator',
    icon: Code2,
  },
  {
    name: 'Settings',
    path: '/settings',
    icon: Settings,
  },
]

function Sidebar() {
  return (
    <aside className="flex h-screen w-64 shrink-0 flex-col border-r border-slate-800 bg-slate-950">
      {/* Brand */}
      <div className="flex h-16 items-center gap-3 border-b border-slate-800 px-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400">
          <ShieldCheck size={22} />
        </div>

        <div>
          <h1 className="text-sm font-bold tracking-wide text-white">
            CyberSentinel
          </h1>

          <p className="text-[10px] uppercase tracking-widest text-slate-500">
            AI Security
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-5">
        {/* Security */}
        <p className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
          Security
        </p>

        <div className="space-y-1">
          {navigation.map((item) => {
            const Icon = item.icon

            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400'
                      : 'text-slate-400 hover:bg-slate-900 hover:text-white'
                  }`
                }
              >
                <Icon size={18} />
                <span>{item.name}</span>
              </NavLink>
            )
          })}
        </div>

        {/* Account */}
        <p className="mb-3 mt-8 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
          Account
        </p>

        <div className="space-y-1">
          {secondaryNavigation.map((item) => {
            const Icon = item.icon

            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400'
                      : 'text-slate-400 hover:bg-slate-900 hover:text-white'
                  }`
                }
              >
                <Icon size={18} />
                <span>{item.name}</span>
              </NavLink>
            )
          })}
        </div>
      </nav>

      {/* Bottom Status */}
      <div className="border-t border-slate-800 p-4">
        <div className="flex items-center gap-2 rounded-lg bg-emerald-500/5 px-3 py-2">
          <span className="h-2 w-2 rounded-full bg-emerald-400" />

          <span className="text-xs text-slate-400">
            Security systems online
          </span>
        </div>
      </div>
    </aside>
  )
}

export default Sidebar