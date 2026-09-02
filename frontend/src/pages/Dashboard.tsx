import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  Cpu,
  Globe2,
  KeyRound,
  Radar,
  ScanSearch,
  Shield,
  ShieldCheck,
  Terminal,
  Zap,
} from 'lucide-react'
import { Link } from 'react-router-dom'

const stats = [
  {
    label: 'Security Score',
    value: '87',
    suffix: '/100',
    icon: ShieldCheck,
    detail: '+6.4% this week',
    tone: 'cyan',
  },
  {
    label: 'URLs Scanned',
    value: '128',
    suffix: '',
    icon: Globe2,
    detail: '12 today',
    tone: 'blue',
  },
  {
    label: 'Threats Detected',
    value: '04',
    suffix: '',
    icon: AlertTriangle,
    detail: '2 require review',
    tone: 'red',
  },
  {
    label: 'Passwords Analyzed',
    value: '36',
    suffix: '',
    icon: KeyRound,
    detail: '94% healthy',
    tone: 'emerald',
  },
]

const recentScans = [
  {
    target: 'example.com',
    type: 'URL Analysis',
    status: 'Safe',
    time: '2 min ago',
  },
  {
    target: 'secure-login.test',
    type: 'URL Analysis',
    status: 'Suspicious',
    time: '18 min ago',
  },
  {
    target: 'Password Audit #024',
    type: 'Password Analysis',
    status: 'Safe',
    time: '42 min ago',
  },
  {
    target: 'cloud-service.test',
    type: 'URL Analysis',
    status: 'Safe',
    time: '1 hr ago',
  },
]

const activity = [
  'URL reputation engine initialized',
  'Security rules updated',
  'Password analysis completed',
  'Threat intelligence synchronized',
]

function Dashboard() {
  return (
    <div className="relative min-h-full overflow-hidden bg-slate-950 text-slate-100">
      {/* Cyber grid */}
      <div className="pointer-events-none absolute inset-0 opacity-[0.035] [background-image:linear-gradient(rgba(34,211,238,1)_1px,transparent_1px),linear-gradient(90deg,rgba(34,211,238,1)_1px,transparent_1px)] [background-size:40px_40px]" />

      <div className="relative mx-auto max-w-[1600px] p-6 md:p-8">

        {/* Header */}
        <header className="mb-8 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.22em] text-cyan-400">
              <Radar size={15} />
              CyberSentinel Command Center
            </div>

            <h1 className="text-3xl font-bold tracking-tight text-white md:text-4xl">
              Security Dashboard
            </h1>

            <p className="mt-2 max-w-2xl text-sm text-slate-500">
              Real-time overview of your security posture, threat activity,
              and analysis operations.
            </p>
          </div>

          <div className="flex w-fit items-center gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-4 py-3">
            <span className="relative flex h-2.5 w-2.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-50" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400" />
            </span>

            <div>
              <p className="text-xs font-semibold text-emerald-400">
                SYSTEM ONLINE
              </p>
              <p className="text-[10px] text-slate-600">
                All security services operational
              </p>
            </div>
          </div>
        </header>

        {/* Stats */}
        <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {stats.map((stat) => {
            const Icon = stat.icon

            return (
              <div
                key={stat.label}
                className="group relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 p-5 transition hover:-translate-y-0.5 hover:border-cyan-500/30"
              >
                <div className="absolute right-0 top-0 h-24 w-24 rounded-full bg-cyan-500/5 blur-2xl transition group-hover:bg-cyan-500/10" />

                <div className="relative flex items-start justify-between">
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                      {stat.label}
                    </p>

                    <div className="mt-3 flex items-baseline gap-1">
                      <span className="text-3xl font-bold text-white">
                        {stat.value}
                      </span>

                      <span className="text-sm text-slate-600">
                        {stat.suffix}
                      </span>
                    </div>
                  </div>

                  <div className="rounded-xl border border-cyan-500/10 bg-cyan-500/5 p-2.5 text-cyan-400">
                    <Icon size={19} />
                  </div>
                </div>

                <div className="relative mt-4 flex items-center gap-2 text-xs">
                  <Activity size={13} className="text-emerald-400" />
                  <span className="text-slate-500">{stat.detail}</span>
                </div>
              </div>
            )
          })}
        </section>

        {/* Main grid */}
        <section className="mt-6 grid gap-6 xl:grid-cols-[1.5fr_1fr]">

          {/* Threat Activity */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <Activity size={17} className="text-cyan-400" />
                  <h2 className="font-semibold text-white">
                    Threat Activity
                  </h2>
                </div>

                <p className="mt-1 text-xs text-slate-600">
                  Security events detected over the last 24 hours
                </p>
              </div>

              <span className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-[10px] uppercase tracking-widest text-slate-500">
                LIVE
              </span>
            </div>

            {/* Cyber graph */}
            <div className="relative mt-8 h-56 overflow-hidden rounded-xl border border-slate-800 bg-slate-950/80">
              <div className="absolute inset-0 opacity-40 [background-image:linear-gradient(rgba(71,85,105,.2)_1px,transparent_1px),linear-gradient(90deg,rgba(71,85,105,.2)_1px,transparent_1px)] [background-size:32px_32px]" />

              <div className="absolute inset-x-0 bottom-10 border-t border-dashed border-slate-800" />
              <div className="absolute inset-x-0 bottom-24 border-t border-dashed border-slate-800" />
              <div className="absolute inset-x-0 bottom-38 border-t border-dashed border-slate-800" />

              <div className="absolute bottom-8 left-5 right-5 flex h-36 items-end gap-2">
                {[35, 52, 28, 68, 45, 82, 56, 38, 74, 48, 91, 63, 78, 42, 69, 54, 88, 61, 72, 49].map(
                  (height, index) => (
                    <div
                      key={index}
                      className={`flex-1 rounded-t-sm transition ${
                        height > 80
                          ? 'bg-red-400/60'
                          : height > 65
                            ? 'bg-amber-400/50'
                            : 'bg-cyan-400/40'
                      }`}
                      style={{ height: `${height}%` }}
                    />
                  ),
                )}
              </div>

              <div className="absolute bottom-2 left-4 right-4 flex justify-between text-[9px] uppercase tracking-widest text-slate-700">
                <span>00:00</span>
                <span>06:00</span>
                <span>12:00</span>
                <span>18:00</span>
                <span>Now</span>
              </div>
            </div>
          </div>

          {/* Security posture */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
            <div className="flex items-center gap-2">
              <Shield size={17} className="text-cyan-400" />
              <h2 className="font-semibold text-white">
                Security Posture
              </h2>
            </div>

            <div className="mt-7 flex items-center justify-center">
              <div className="relative flex h-48 w-48 items-center justify-center rounded-full border border-cyan-500/10">
                <div className="absolute inset-3 rounded-full border border-cyan-500/20" />
                <div className="absolute inset-6 rounded-full border border-cyan-500/10" />

                <div className="text-center">
                  <p className="text-5xl font-bold text-cyan-400">
                    87
                  </p>
                  <p className="mt-1 text-[10px] uppercase tracking-[0.2em] text-slate-600">
                    Security Score
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-6 flex items-center justify-center gap-2 text-xs text-emerald-400">
              <CheckCircle2 size={14} />
              Security posture is healthy
            </div>
          </div>
        </section>

        {/* Quick actions */}
        <section className="mt-6">
          <div className="mb-4 flex items-center gap-2">
            <Zap size={17} className="text-cyan-400" />
            <h2 className="font-semibold text-white">
              Quick Operations
            </h2>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <Link
              to="/url-scanner"
              className="group flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/60 p-5 transition hover:border-cyan-500/30 hover:bg-cyan-500/[0.03]"
            >
              <div className="flex items-center gap-4">
                <div className="rounded-xl bg-cyan-500/10 p-3 text-cyan-400">
                  <ScanSearch size={22} />
                </div>

                <div>
                  <h3 className="font-semibold text-white">
                    Scan a URL
                  </h3>
                  <p className="mt-1 text-xs text-slate-600">
                    Analyze a website for suspicious indicators
                  </p>
                </div>
              </div>

              <ArrowUpRight
                size={19}
                className="text-slate-700 transition group-hover:text-cyan-400"
              />
            </Link>

            <Link
              to="/password-analyzer"
              className="group flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/60 p-5 transition hover:border-cyan-500/30 hover:bg-cyan-500/[0.03]"
            >
              <div className="flex items-center gap-4">
                <div className="rounded-xl bg-cyan-500/10 p-3 text-cyan-400">
                  <KeyRound size={22} />
                </div>

                <div>
                  <h3 className="font-semibold text-white">
                    Analyze Password
                  </h3>
                  <p className="mt-1 text-xs text-slate-600">
                    Check password strength and exposure risks
                  </p>
                </div>
              </div>

              <ArrowUpRight
                size={19}
                className="text-slate-700 transition group-hover:text-cyan-400"
              />
            </Link>
          </div>
        </section>

        {/* Bottom section */}
        <section className="mt-6 grid gap-6 xl:grid-cols-[1.4fr_1fr]">

          {/* Recent scans */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <h2 className="font-semibold text-white">
                  Recent Security Operations
                </h2>
                <p className="mt-1 text-xs text-slate-600">
                  Latest analysis activity
                </p>
              </div>

              <Link
                to="/scan-history"
                className="text-xs text-cyan-400 hover:text-cyan-300"
              >
                View all
              </Link>
            </div>

            <div className="space-y-2">
              {recentScans.map((scan) => (
                <div
                  key={`${scan.target}-${scan.time}`}
                  className="flex items-center justify-between rounded-xl border border-slate-800/70 bg-slate-950/40 px-4 py-3"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <Terminal
                      size={15}
                      className="shrink-0 text-slate-600"
                    />

                    <div className="min-w-0">
                      <p className="truncate text-sm text-slate-300">
                        {scan.target}
                      </p>
                      <p className="mt-0.5 text-[10px] uppercase tracking-wider text-slate-700">
                        {scan.type}
                      </p>
                    </div>
                  </div>

                  <div className="ml-4 flex shrink-0 items-center gap-3">
                    <span
                      className={`text-[10px] font-semibold uppercase tracking-wider ${
                        scan.status === 'Safe'
                          ? 'text-emerald-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {scan.status}
                    </span>

                    <span className="hidden text-[10px] text-slate-700 sm:block">
                      {scan.time}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* System activity */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
            <div className="flex items-center gap-2">
              <Cpu size={17} className="text-cyan-400" />
              <h2 className="font-semibold text-white">
                System Activity
              </h2>
            </div>

            <div className="mt-5 space-y-5">
              {activity.map((item, index) => (
                <div key={item} className="flex gap-3">
                  <div className="relative flex w-4 justify-center">
                    <span className="mt-1.5 h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_10px_rgba(34,211,238,.5)]" />

                    {index !== activity.length - 1 && (
                      <span className="absolute top-4 h-full w-px bg-slate-800" />
                    )}
                  </div>

                  <div className="flex-1">
                    <p className="text-xs text-slate-400">
                      {item}
                    </p>

                    <div className="mt-1 flex items-center gap-1 text-[10px] text-slate-700">
                      <Clock3 size={10} />
                      {index === 0
                        ? 'Just now'
                        : `${index * 8} min ago`}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-6 flex items-center gap-2 rounded-lg border border-emerald-500/10 bg-emerald-500/[0.03] px-3 py-2.5">
              <CheckCircle2 size={14} className="text-emerald-400" />
              <span className="text-[10px] uppercase tracking-wider text-slate-600">
                Security engine operational
              </span>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}

export default Dashboard