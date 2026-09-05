import { useEffect, useState } from 'react'
import { apiFetch } from '../lib/api'

import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Clock3,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'

type DashboardStats = {
  total_scans: number
  safe_urls: number
  suspicious_urls: number
  threats_detected: number
  average_risk_score: number
}

type HistoryItem = {
  id: number
  url: string
  domain: string
  score: number
  status: 'safe' | 'suspicious' | 'threat'
  risk_level: string
  summary: string
  scanned_at?: string
}

const API_BASE = 'http://127.0.0.1:8000'

const emptyStats: DashboardStats = {
  total_scans: 0,
  safe_urls: 0,
  suspicious_urls: 0,
  threats_detected: 0,
  average_risk_score: 0,
}

function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>(emptyStats)
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const loadDashboard = async () => {
    try {
      setLoading(true)
      setError('')

     const [statsResponse, historyResponse] = await Promise.all([
     apiFetch('/api/scan/stats'),
     apiFetch('/api/scan/history'),
     ])

      const statsData = await statsResponse.json()
      const historyData = await historyResponse.json()

      if (!statsResponse.ok || !statsData.success) {
        throw new Error(statsData.error || 'Unable to load dashboard statistics.')
      }

      if (!historyResponse.ok || !historyData.success) {
        throw new Error(historyData.error || 'Unable to load recent scan history.')
      }

      // Supports the current backend shape: { success: true, stats: {...} }
      const rawStats = statsData.stats ?? statsData

      setStats({
        total_scans: Number(rawStats.total_scans ?? 0),
        safe_urls: Number(rawStats.safe_urls ?? 0),
        suspicious_urls: Number(rawStats.suspicious_urls ?? 0),
        threats_detected: Number(
          rawStats.threats_detected ?? rawStats.threats ?? 0,
        ),
        average_risk_score: Number(
          rawStats.average_risk_score ?? rawStats.avg_risk_score ?? 0,
        ),
      })

      setHistory((historyData.history ?? []).slice(0, 5))
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to connect to CyberSentinel API.',
      )
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadDashboard()
  }, [])

  const formatDate = (value?: string) => {
    if (!value) return 'Unknown time'

    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return value

    return date.toLocaleString([], {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  }

  const getStatusClass = (status: HistoryItem['status']) => {
    if (status === 'threat') {
      return 'border-red-500/20 bg-red-500/5 text-red-400'
    }

    if (status === 'suspicious') {
      return 'border-yellow-500/20 bg-yellow-500/5 text-yellow-400'
    }

    return 'border-emerald-500/20 bg-emerald-500/5 text-emerald-400'
  }

  const safePercent =
    stats.total_scans > 0 ? (stats.safe_urls / stats.total_scans) * 100 : 0
  const suspiciousPercent =
    stats.total_scans > 0
      ? (stats.suspicious_urls / stats.total_scans) * 100
      : 0
  const threatPercent =
    stats.total_scans > 0
      ? (stats.threats_detected / stats.total_scans) * 100
      : 0

  return (
    <div className="min-h-full bg-slate-950 px-6 py-8 text-slate-100 md:px-10">
      <div className="mx-auto max-w-7xl">
        {/* Dashboard Header */}
        <div className="mb-8 flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="mb-3 flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-400">
                <BarChart3 size={23} />
              </div>

              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
                  CyberSentinel / Security Center
                </p>
                <h1 className="text-3xl font-bold tracking-tight text-white">
                  Security Dashboard
                </h1>
              </div>
            </div>

            <p className="max-w-2xl text-sm leading-6 text-slate-400">
              Monitor your URL security activity, risk levels, and recent
              security assessments from one place.
            </p>
          </div>

          <button
            type="button"
            onClick={() => void loadDashboard()}
            disabled={loading}
            className="flex h-11 items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-5 text-sm font-semibold text-slate-300 transition hover:border-cyan-500/40 hover:text-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>

        {error && (
          <div className="mb-6 rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}

        {/* Overview Cards */}
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                Total Scans
              </span>
              <Activity size={18} className="text-cyan-400" />
            </div>
            <p className="mt-4 text-3xl font-black text-white">
              {loading ? '—' : stats.total_scans}
            </p>
            <p className="mt-1 text-xs text-slate-600">All saved URL scans</p>
          </div>

          <div className="rounded-2xl border border-emerald-500/10 bg-emerald-500/5 p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                Safe URLs
              </span>
              <CheckCircle2 size={18} className="text-emerald-400" />
            </div>
            <p className="mt-4 text-3xl font-black text-emerald-400">
              {loading ? '—' : stats.safe_urls}
            </p>
            <p className="mt-1 text-xs text-slate-600">Low-risk assessments</p>
          </div>

          <div className="rounded-2xl border border-yellow-500/10 bg-yellow-500/5 p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                Suspicious
              </span>
              <AlertTriangle size={18} className="text-yellow-400" />
            </div>
            <p className="mt-4 text-3xl font-black text-yellow-400">
              {loading ? '—' : stats.suspicious_urls}
            </p>
            <p className="mt-1 text-xs text-slate-600">Needs attention</p>
          </div>

          <div className="rounded-2xl border border-red-500/10 bg-red-500/5 p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                Threats
              </span>
              <ShieldAlert size={18} className="text-red-400" />
            </div>
            <p className="mt-4 text-3xl font-black text-red-400">
              {loading ? '—' : stats.threats_detected}
            </p>
            <p className="mt-1 text-xs text-slate-600">Threat classifications</p>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                Avg Risk
              </span>
              <BarChart3 size={18} className="text-cyan-400" />
            </div>
            <p className="mt-4 text-3xl font-black text-white">
              {loading ? '—' : stats.average_risk_score.toFixed(1)}
              <span className="ml-1 text-sm font-medium text-slate-600">
                /100
              </span>
            </p>
            <p className="mt-1 text-xs text-slate-600">Average risk score</p>
          </div>
        </div>

        {/* Analytics */}
        <div className="mt-6 grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
            <div className="mb-6">
              <div className="flex items-center gap-2">
                <BarChart3 size={18} className="text-cyan-400" />
                <p className="text-xs font-semibold uppercase tracking-widest text-cyan-400">
                  Risk Analytics
                </p>
              </div>
              <h2 className="mt-1 text-xl font-bold text-white">
                Scan Distribution
              </h2>
            </div>

            {stats.total_scans === 0 && !loading ? (
              <div className="rounded-xl border border-dashed border-slate-800 bg-slate-950/40 p-10 text-center">
                <ShieldCheck size={30} className="mx-auto mb-3 text-slate-700" />
                <p className="text-sm font-medium text-slate-400">
                  No scan data yet
                </p>
                <p className="mt-1 text-xs text-slate-600">
                  Run your first URL scan to populate the dashboard.
                </p>
              </div>
            ) : (
              <div>
                <div className="flex h-5 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className="bg-emerald-400 transition-all"
                    style={{ width: `${safePercent}%` }}
                    title={`Safe: ${stats.safe_urls}`}
                  />
                  <div
                    className="bg-yellow-400 transition-all"
                    style={{ width: `${suspiciousPercent}%` }}
                    title={`Suspicious: ${stats.suspicious_urls}`}
                  />
                  <div
                    className="bg-red-400 transition-all"
                    style={{ width: `${threatPercent}%` }}
                    title={`Threats: ${stats.threats_detected}`}
                  />
                </div>

                <div className="mt-6 grid gap-3 sm:grid-cols-3">
                  <div className="rounded-xl border border-emerald-500/10 bg-emerald-500/5 p-4">
                    <p className="text-xs uppercase tracking-widest text-slate-500">
                      Safe
                    </p>
                    <p className="mt-2 text-2xl font-black text-emerald-400">
                      {stats.safe_urls}
                    </p>
                    <p className="text-xs text-slate-600">
                      {safePercent.toFixed(1)}%
                    </p>
                  </div>

                  <div className="rounded-xl border border-yellow-500/10 bg-yellow-500/5 p-4">
                    <p className="text-xs uppercase tracking-widest text-slate-500">
                      Suspicious
                    </p>
                    <p className="mt-2 text-2xl font-black text-yellow-400">
                      {stats.suspicious_urls}
                    </p>
                    <p className="text-xs text-slate-600">
                      {suspiciousPercent.toFixed(1)}%
                    </p>
                  </div>

                  <div className="rounded-xl border border-red-500/10 bg-red-500/5 p-4">
                    <p className="text-xs uppercase tracking-widest text-slate-500">
                      Threats
                    </p>
                    <p className="mt-2 text-2xl font-black text-red-400">
                      {stats.threats_detected}
                    </p>
                    <p className="text-xs text-slate-600">
                      {threatPercent.toFixed(1)}%
                    </p>
                  </div>
                </div>
              </div>
            )}
          </section>

          {/* Recent Activity */}
          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
            <div className="mb-5">
              <div className="flex items-center gap-2">
                <Clock3 size={18} className="text-cyan-400" />
                <p className="text-xs font-semibold uppercase tracking-widest text-cyan-400">
                  Recent Activity
                </p>
              </div>
              <h2 className="mt-1 text-xl font-bold text-white">
                Latest Scans
              </h2>
            </div>

            {loading ? (
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-6 text-center text-sm text-slate-500">
                Loading recent activity...
              </div>
            ) : history.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-800 bg-slate-950/40 p-8 text-center">
                <Activity size={28} className="mx-auto mb-3 text-slate-700" />
                <p className="text-sm text-slate-400">No recent scans</p>
              </div>
            ) : (
              <div className="space-y-3">
                {history.map((item) => (
                  <div
                    key={item.id}
                    className="rounded-xl border border-slate-800 bg-slate-950/50 p-4"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate font-mono text-sm text-cyan-400">
                          {item.domain || item.url}
                        </p>
                        <p className="mt-1 text-xs text-slate-600">
                          {formatDate(item.scanned_at)}
                        </p>
                      </div>

                      <div className="flex shrink-0 items-center gap-2">
                        <span
                          className={`rounded-lg border px-2.5 py-1 text-xs font-semibold ${getStatusClass(item.status)}`}
                        >
                          {item.risk_level}
                        </span>
                        <span className="text-sm font-black text-white">
                          {item.score}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>

        {/* Footer Status */}
        <div className="mt-6 flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/50 px-4 py-3 text-xs text-slate-500">
          <span className="h-2 w-2 rounded-full bg-emerald-400" />
          Dashboard connected to CyberSentinel local security API
        </div>
      </div>
    </div>
  )
}

export default Dashboard