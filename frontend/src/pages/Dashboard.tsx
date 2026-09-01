import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  KeyRound,
  ScanSearch,
  ShieldCheck,
  ShieldAlert,
  Zap,
} from 'lucide-react'

const stats = [
  {
    title: 'Security Score',
    value: '82',
    suffix: '/100',
    change: '+6%',
    icon: ShieldCheck,
    description: 'Good security posture',
  },
  {
    title: 'URLs Scanned',
    value: '128',
    change: '+18',
    icon: ScanSearch,
    description: 'This month',
  },
  {
    title: 'Threats Detected',
    value: '17',
    change: '-12%',
    icon: ShieldAlert,
    description: 'Compared with last month',
  },
  {
    title: 'Passwords Analyzed',
    value: '64',
    change: '+9',
    icon: KeyRound,
    description: 'Security checks completed',
  },
]

const recentScans = [
  {
    target: 'example.com',
    type: 'URL Scan',
    status: 'Safe',
    time: '2 min ago',
  },
  {
    target: 'login-example.net',
    type: 'URL Scan',
    status: 'Suspicious',
    time: '18 min ago',
  },
  {
    target: 'my-account.com',
    type: 'URL Scan',
    status: 'Safe',
    time: '42 min ago',
  },
  {
    target: 'secure-payment.co',
    type: 'URL Scan',
    status: 'Threat',
    time: '1 hr ago',
  },
]

function Dashboard() {
  return (
    <div className="min-h-full bg-slate-950 p-6 text-slate-100 md:p-8">
      <div className="mx-auto max-w-7xl">

        {/* Header */}
        <div className="mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <div className="mb-2 flex items-center gap-2 text-sm text-cyan-400">
              <Activity size={16} />
              Security Command Center
            </div>

            <h1 className="text-3xl font-bold tracking-tight">
              Security Dashboard
            </h1>

            <p className="mt-2 text-sm text-slate-400">
              Monitor your security posture and recent threat activity.
            </p>
          </div>

          <button className="flex w-fit items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400">
            <Zap size={17} />
            Quick Scan
          </button>
        </div>

        {/* Stats */}
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {stats.map((stat) => {
            const Icon = stat.icon

            return (
              <div
                key={stat.title}
                className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 transition hover:border-slate-700"
              >
                <div className="flex items-start justify-between">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400">
                    <Icon size={20} />
                  </div>

                  <span className="text-xs font-medium text-emerald-400">
                    {stat.change}
                  </span>
                </div>

                <p className="mt-5 text-sm text-slate-400">
                  {stat.title}
                </p>

                <div className="mt-1 flex items-baseline gap-1">
                  <span className="text-3xl font-bold text-white">
                    {stat.value}
                  </span>

                  {stat.suffix && (
                    <span className="text-sm text-slate-500">
                      {stat.suffix}
                    </span>
                  )}
                </div>

                <p className="mt-2 text-xs text-slate-500">
                  {stat.description}
                </p>
              </div>
            )
          })}
        </div>

        {/* Main grid */}
        <div className="mt-6 grid gap-6 xl:grid-cols-3">

          {/* Security Score */}
          <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 xl:col-span-1">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="font-semibold">Security Posture</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Overall system assessment
                </p>
              </div>

              <ShieldCheck className="text-cyan-400" size={22} />
            </div>

            <div className="mt-8 flex justify-center">
              <div className="flex h-40 w-40 items-center justify-center rounded-full border-[10px] border-cyan-500/20">
                <div className="text-center">
                  <div className="text-4xl font-bold text-white">82</div>
                  <div className="text-xs text-slate-500">out of 100</div>
                </div>
              </div>
            </div>

            <div className="mt-7">
              <div className="mb-2 flex justify-between text-xs">
                <span className="text-slate-400">Security level</span>
                <span className="font-medium text-cyan-400">Good</span>
              </div>

              <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                <div className="h-full w-[82%] rounded-full bg-cyan-500" />
              </div>
            </div>
          </section>

          {/* Threat Activity */}
          <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 xl:col-span-2">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="font-semibold">Threat Activity</h2>
                <p className="mt-1 text-xs text-slate-500">
                  Security events detected recently
                </p>
              </div>

              <button className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300">
                View history
                <ArrowUpRight size={14} />
              </button>
            </div>

            <div className="mt-8 grid grid-cols-3 gap-4">
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                <CheckCircle2 className="text-emerald-400" size={20} />
                <p className="mt-4 text-2xl font-bold">111</p>
                <p className="mt-1 text-xs text-slate-500">Safe</p>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                <AlertTriangle className="text-amber-400" size={20} />
                <p className="mt-4 text-2xl font-bold">12</p>
                <p className="mt-1 text-xs text-slate-500">Suspicious</p>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                <ShieldAlert className="text-red-400" size={20} />
                <p className="mt-4 text-2xl font-bold">5</p>
                <p className="mt-1 text-xs text-slate-500">Threats</p>
              </div>
            </div>

            <div className="mt-6 rounded-lg border border-cyan-500/10 bg-cyan-500/5 p-4">
              <div className="flex gap-3">
                <Activity className="mt-0.5 shrink-0 text-cyan-400" size={18} />

                <div>
                  <p className="text-sm font-medium text-white">
                    AI Security Insight
                  </p>

                  <p className="mt-1 text-xs leading-5 text-slate-400">
                    Your current security posture is good. Review the
                    suspicious URLs detected in your recent activity.
                  </p>
                </div>
              </div>
            </div>
          </section>
        </div>

        {/* Recent Scans */}
        <section className="mt-6 rounded-xl border border-slate-800 bg-slate-900/60">
          <div className="flex items-center justify-between border-b border-slate-800 p-6">
            <div>
              <h2 className="font-semibold">Recent Scans</h2>
              <p className="mt-1 text-xs text-slate-500">
                Latest security analysis activity
              </p>
            </div>

            <button className="text-xs text-cyan-400 hover:text-cyan-300">
              View all
            </button>
          </div>

          <div className="divide-y divide-slate-800">
            {recentScans.map((scan) => (
              <div
                key={`${scan.target}-${scan.time}`}
                className="flex flex-col gap-3 p-5 transition hover:bg-slate-900 md:flex-row md:items-center md:justify-between"
              >
                <div className="flex items-center gap-4">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-800">
                    <ScanSearch size={17} className="text-slate-400" />
                  </div>

                  <div>
                    <p className="text-sm font-medium text-white">
                      {scan.target}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      {scan.type} · {scan.time}
                    </p>
                  </div>
                </div>

                <span
                  className={`w-fit rounded-full px-3 py-1 text-xs font-medium ${
                    scan.status === 'Safe'
                      ? 'bg-emerald-500/10 text-emerald-400'
                      : scan.status === 'Suspicious'
                        ? 'bg-amber-500/10 text-amber-400'
                        : 'bg-red-500/10 text-red-400'
                  }`}
                >
                  {scan.status}
                </span>
              </div>
            ))}
          </div>
        </section>

      </div>
    </div>
  )
}

export default Dashboard