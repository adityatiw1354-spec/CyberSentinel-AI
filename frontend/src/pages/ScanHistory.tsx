import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Eye,
  FileDown,
  History,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  XCircle,
} from 'lucide-react'

type Indicator = {
  label: string
  value: string
  safe: boolean
}

type HistoryItem = {
  id: number
  url: string
  domain: string
  score: number
  status: 'safe' | 'suspicious' | 'threat'
  risk_level: string
  summary: string
  indicators: Indicator[]
  scanned_at: string
}

function ScanHistory() {
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<
    'all' | 'safe' | 'suspicious' | 'threat'
  >('all')
  const [selectedScan, setSelectedScan] =
    useState<HistoryItem | null>(null)
  const [reportGenerating, setReportGenerating] = useState(false)

  const loadHistory = async (showRefresh = false) => {
    try {
      if (showRefresh) {
        setRefreshing(true)
      } else {
        setLoading(true)
      }

      setError('')

      const response = await fetch(
        'http://127.0.0.1:8000/api/scan/history',
      )

      let data: {
        success?: boolean
        history?: HistoryItem[]
        error?: string
      }

      try {
        data = await response.json()
      } catch {
        throw new Error(
          `History request failed (HTTP ${response.status}).`,
        )
      }

      if (!response.ok || !data.success) {
        throw new Error(
          data.error || 'Unable to load scan history.',
        )
      }

      setHistory(data.history ?? [])
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to load scan history.',
      )
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    void loadHistory()
  }, [])

  const clearHistory = async () => {
    if (history.length === 0) return

    const confirmed = window.confirm(
      'Are you sure you want to clear all scan history?',
    )

    if (!confirmed) return

    try {
      setError('')

      const response = await fetch(
        'http://127.0.0.1:8000/api/scan/history',
        {
          method: 'DELETE',
        },
      )

      let data: {
        success?: boolean
        error?: string
      }

      try {
        data = await response.json()
      } catch {
        throw new Error(
          `Clear history failed (HTTP ${response.status}).`,
        )
      }

      if (!response.ok || !data.success) {
        throw new Error(
          data.error || 'Unable to clear scan history.',
        )
      }

      setHistory([])
      setSelectedScan(null)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to clear scan history.',
      )
    }
  }

  const formatScanTime = (value: string) => {
    const date = new Date(value)

    if (Number.isNaN(date.getTime())) {
      return value
    }

    return date.toLocaleString([], {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  }

  const filteredHistory = useMemo(() => {
    const query = search.trim().toLowerCase()

    return history.filter((item) => {
      const matchesSearch =
        !query ||
        item.url.toLowerCase().includes(query) ||
        item.domain.toLowerCase().includes(query)

      const matchesFilter =
        filter === 'all' || item.status === filter

      return matchesSearch && matchesFilter
    })
  }, [history, search, filter])

  const counts = useMemo(() => {
    return {
      total: history.length,
      safe: history.filter((item) => item.status === 'safe').length,
      suspicious: history.filter(
        (item) => item.status === 'suspicious',
      ).length,
      threat: history.filter(
        (item) => item.status === 'threat',
      ).length,
    }
  }, [history])

  const generateReport = async (scan: HistoryItem) => {
    if (reportGenerating) return

    try {
      setReportGenerating(true)
      setError('')

      const response = await fetch(
        'http://127.0.0.1:8000/api/report/pdf',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            url: scan.url,
            score: scan.score,
            status: scan.status,
            risk_level: scan.risk_level,
            summary: scan.summary,
            indicators: scan.indicators,
            scanned_at: scan.scanned_at,
          }),
        },
      )

      if (!response.ok) {
        let message = `Report generation failed (HTTP ${response.status}).`

        try {
          const data = await response.json()
          message = data.error || message
        } catch {
          // Keep HTTP fallback message.
        }

        throw new Error(message)
      }

      const blob = await response.blob()
      const downloadUrl = window.URL.createObjectURL(blob)

      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = 'CyberSentinel_Security_Report.pdf'

      document.body.appendChild(link)
      link.click()
      link.remove()

      window.URL.revokeObjectURL(downloadUrl)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to generate security report.',
      )
    } finally {
      setReportGenerating(false)
    }
  }

  const getStatusIcon = (
    status: HistoryItem['status'],
    size = 19,
  ) => {
    if (status === 'safe') {
      return (
        <CheckCircle2
          size={size}
          className="text-emerald-400"
        />
      )
    }

    if (status === 'suspicious') {
      return (
        <AlertTriangle
          size={size}
          className="text-yellow-400"
        />
      )
    }

    return (
      <ShieldAlert
        size={size}
        className="text-red-400"
      />
    )
  }

  const getStatusLabel = (
    status: HistoryItem['status'],
  ) => {
    if (status === 'safe') return 'Safe'
    if (status === 'suspicious') return 'Suspicious'
    return 'Threat'
  }

  const getStatusClass = (
    status: HistoryItem['status'],
  ) => {
    if (status === 'safe') {
      return 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
    }

    if (status === 'suspicious') {
      return 'border-yellow-500/20 bg-yellow-500/10 text-yellow-400'
    }

    return 'border-red-500/20 bg-red-500/10 text-red-400'
  }

  const getScoreClass = (score: number) => {
    if (score >= 70) return 'text-emerald-400'
    if (score >= 40) return 'text-yellow-400'
    return 'text-red-400'
  }

  return (
    <div className="min-h-full bg-slate-950 px-6 py-8 text-slate-100 md:px-10">
      <div className="mx-auto max-w-6xl">

        {/* Header */}
        <div className="mb-8 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">

          <div>
            <div className="mb-3 flex items-center gap-3">

              <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-400">
                <History size={23} />
              </div>

              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
                  CyberSentinel / Intelligence
                </p>

                <h1 className="text-3xl font-bold tracking-tight text-white">
                  Scan History
                </h1>
              </div>

            </div>

            <p className="max-w-2xl text-sm leading-6 text-slate-400">
              Review previous URL security scans, inspect risk
              intelligence, and generate reports from historical results.
            </p>
          </div>

          <div className="flex gap-3">

            <button
              type="button"
              onClick={() => void loadHistory(true)}
              disabled={refreshing || loading}
              className="flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm font-semibold text-slate-300 transition hover:border-cyan-500/40 hover:text-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <RefreshCw
                size={17}
                className={
                  refreshing ? 'animate-spin' : ''
                }
              />
              Refresh
            </button>

            <button
              type="button"
              onClick={() => void clearHistory()}
              disabled={history.length === 0 || loading}
              className="flex items-center justify-center gap-2 rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-2.5 text-sm font-semibold text-red-400 transition hover:bg-red-500/10 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Trash2 size={17} />
              Clear History
            </button>

          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="mb-6 flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">

            <XCircle
              size={19}
              className="mt-0.5 shrink-0"
            />

            <div>
              <p className="font-semibold">
                History operation failed
              </p>

              <p className="mt-1 text-red-400/80">
                {error}
              </p>
            </div>

          </div>
        )}

        {/* Summary Cards */}
        <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">

          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
              Total Scans
            </p>

            <p className="mt-3 text-3xl font-black text-white">
              {counts.total}
            </p>

            <p className="mt-1 text-xs text-slate-600">
              Stored security assessments
            </p>
          </div>

          <div className="rounded-2xl border border-emerald-500/10 bg-slate-900/70 p-5">
            <div className="flex items-center justify-between">
              <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                Safe
              </p>

              <CheckCircle2
                size={18}
                className="text-emerald-400"
              />
            </div>

            <p className="mt-3 text-3xl font-black text-emerald-400">
              {counts.safe}
            </p>
          </div>

          <div className="rounded-2xl border border-yellow-500/10 bg-slate-900/70 p-5">
            <div className="flex items-center justify-between">
              <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                Suspicious
              </p>

              <AlertTriangle
                size={18}
                className="text-yellow-400"
              />
            </div>

            <p className="mt-3 text-3xl font-black text-yellow-400">
              {counts.suspicious}
            </p>
          </div>

          <div className="rounded-2xl border border-red-500/10 bg-slate-900/70 p-5">
            <div className="flex items-center justify-between">
              <p className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                Threats
              </p>

              <ShieldAlert
                size={18}
                className="text-red-400"
              />
            </div>

            <p className="mt-3 text-3xl font-black text-red-400">
              {counts.threat}
            </p>
          </div>

        </div>

        {/* Search + Filters */}
        <div className="mb-6 rounded-2xl border border-slate-800 bg-slate-900/70 p-4">

          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">

            <div className="relative flex-1">

              <Search
                size={18}
                className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600"
              />

              <input
                type="text"
                value={search}
                onChange={(event) =>
                  setSearch(event.target.value)
                }
                placeholder="Search URL or domain..."
                className="h-11 w-full rounded-xl border border-slate-700 bg-slate-950/70 pl-11 pr-4 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10"
              />

            </div>

            <div className="flex flex-wrap gap-2">

              {(
                [
                  ['all', 'All'],
                  ['safe', 'Safe'],
                  ['suspicious', 'Suspicious'],
                  ['threat', 'Threat'],
                ] as const
              ).map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setFilter(value)}
                  className={`rounded-lg px-4 py-2 text-xs font-semibold transition ${
                    filter === value
                      ? 'bg-cyan-500 text-slate-950'
                      : 'border border-slate-700 bg-slate-950 text-slate-400 hover:border-slate-600 hover:text-white'
                  }`}
                >
                  {label}
                </button>
              ))}

            </div>

          </div>

          <div className="mt-3 text-xs text-slate-600">
            Showing {filteredHistory.length} of {history.length} scans
          </div>

        </div>

        {/* Loading */}
        {loading && (
          <div className="rounded-2xl border border-cyan-500/20 bg-cyan-500/5 p-12 text-center">

            <Loader2
              size={30}
              className="mx-auto animate-spin text-cyan-400"
            />

            <p className="mt-4 text-sm font-semibold text-white">
              Loading scan history...
            </p>

          </div>
        )}

        {/* Empty */}
        {!loading && history.length === 0 && (
          <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-950/40 p-14 text-center">

            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-slate-800 bg-slate-900 text-slate-700">
              <History size={25} />
            </div>

            <h2 className="text-lg font-semibold text-slate-300">
              No scan history yet
            </h2>

            <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-600">
              Run a URL security scan from the URL Scanner page.
              Successful scans will appear here automatically.
            </p>

          </div>
        )}

        {/* No Search Results */}
        {!loading &&
          history.length > 0 &&
          filteredHistory.length === 0 && (
            <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-950/40 p-12 text-center">

              <Search
                size={28}
                className="mx-auto text-slate-700"
              />

              <h2 className="mt-4 text-lg font-semibold text-slate-300">
                No matching scans
              </h2>

              <p className="mt-2 text-sm text-slate-600">
                Try another URL, domain, or status filter.
              </p>

            </div>
          )}

        {/* History List */}
        {!loading && filteredHistory.length > 0 && (
          <div className="space-y-3">

            {filteredHistory.map((scan) => (
              <div
                key={scan.id}
                className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 transition hover:border-slate-700"
              >

                <div className="flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">

                  {/* Main */}
                  <div className="min-w-0 flex-1">

                    <div className="flex items-start gap-3">

                      <div
                        className={`mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${getStatusClass(
                          scan.status,
                        )}`}
                      >
                        {getStatusIcon(scan.status, 20)}
                      </div>

                      <div className="min-w-0">

                        <div className="flex flex-wrap items-center gap-2">

                          <h2 className="truncate text-sm font-semibold text-white">
                            {scan.domain || scan.url}
                          </h2>

                          <span
                            className={`rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider ${getStatusClass(
                              scan.status,
                            )}`}
                          >
                            {getStatusLabel(scan.status)}
                          </span>

                        </div>

                        <p className="mt-1 break-all text-xs text-slate-500">
                          {scan.url}
                        </p>

                        <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-slate-600">

                          <span className="flex items-center gap-1.5">
                            <Clock3 size={13} />
                            {formatScanTime(scan.scanned_at)}
                          </span>

                          <span>
                            Risk: {scan.risk_level}
                          </span>

                        </div>

                      </div>

                    </div>

                  </div>

                  {/* Score */}
                  <div className="flex items-center gap-6 xl:shrink-0">

                    <div className="text-left xl:text-right">
                      <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-600">
                        Risk Score
                      </p>

                      <p
                        className={`mt-1 text-2xl font-black ${getScoreClass(
                          scan.score,
                        )}`}
                      >
                        {scan.score}
                        <span className="text-xs font-medium text-slate-600">
                          /100
                        </span>
                      </p>
                    </div>

                    <div className="flex gap-2">

                      <button
                        type="button"
                        onClick={() => setSelectedScan(scan)}
                        className="flex h-10 items-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs font-semibold text-slate-300 transition hover:border-cyan-500/40 hover:text-cyan-400"
                      >
                        <Eye size={15} />
                        View
                      </button>

                      <button
                        type="button"
                        onClick={() => void generateReport(scan)}
                        disabled={reportGenerating}
                        className="flex h-10 items-center gap-2 rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-3 text-xs font-semibold text-cyan-400 transition hover:bg-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <FileDown size={15} />
                        PDF
                      </button>

                    </div>

                  </div>

                </div>

              </div>
            ))}

          </div>
        )}

        {/* Selected Scan Modal */}
        {selectedScan && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
            onClick={() => setSelectedScan(null)}
          >
            <div
              className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-2xl border border-slate-800 bg-slate-950 shadow-2xl"
              onClick={(event) => event.stopPropagation()}
            >

              <div className="sticky top-0 flex items-center justify-between border-b border-slate-800 bg-slate-950/95 px-6 py-5 backdrop-blur">

                <div className="flex items-center gap-3">

                  <div
                    className={`flex h-10 w-10 items-center justify-center rounded-xl border ${getStatusClass(
                      selectedScan.status,
                    )}`}
                  >
                    {getStatusIcon(
                      selectedScan.status,
                      20,
                    )}
                  </div>

                  <div>
                    <h2 className="text-lg font-bold text-white">
                      Scan Details
                    </h2>

                    <p className="text-xs text-slate-600">
                      Scan #{selectedScan.id}
                    </p>
                  </div>

                </div>

                <button
                  type="button"
                  onClick={() => setSelectedScan(null)}
                  className="rounded-lg p-2 text-slate-500 transition hover:bg-slate-900 hover:text-white"
                  aria-label="Close scan details"
                >
                  <XCircle size={21} />
                </button>

              </div>

              <div className="space-y-5 p-6">

                {/* URL */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">

                  <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-600">
                    Scanned URL
                  </p>

                  <p className="mt-2 break-all text-sm leading-6 text-white">
                    {selectedScan.url}
                  </p>

                  <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-500">

                    <span>
                      Domain: {selectedScan.domain}
                    </span>

                    <span>
                      Time: {formatScanTime(
                        selectedScan.scanned_at,
                      )}
                    </span>

                  </div>

                </div>

                {/* Assessment */}
                <div className="grid gap-4 sm:grid-cols-3">

                  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                    <p className="text-[10px] uppercase tracking-widest text-slate-600">
                      Score
                    </p>

                    <p
                      className={`mt-2 text-3xl font-black ${getScoreClass(
                        selectedScan.score,
                      )}`}
                    >
                      {selectedScan.score}
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                    <p className="text-[10px] uppercase tracking-widest text-slate-600">
                      Risk Level
                    </p>

                    <p className="mt-2 text-lg font-bold text-white">
                      {selectedScan.risk_level}
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                    <p className="text-[10px] uppercase tracking-widest text-slate-600">
                      Status
                    </p>

                    <p
                      className={`mt-2 text-lg font-bold ${
                        selectedScan.status === 'safe'
                          ? 'text-emerald-400'
                          : selectedScan.status ===
                              'suspicious'
                            ? 'text-yellow-400'
                            : 'text-red-400'
                      }`}
                    >
                      {getStatusLabel(
                        selectedScan.status,
                      )}
                    </p>
                  </div>

                </div>

                {/* Summary */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">

                  <div className="flex items-center gap-2">
                    <ShieldCheck
                      size={18}
                      className="text-cyan-400"
                    />

                    <h3 className="text-sm font-semibold text-white">
                      Security Summary
                    </h3>
                  </div>

                  <p className="mt-3 text-sm leading-6 text-slate-400">
                    {selectedScan.summary}
                  </p>

                </div>

                {/* Indicators */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">

                  <h3 className="text-sm font-semibold text-white">
                    Security Indicators
                  </h3>

                  <div className="mt-4 grid gap-3 sm:grid-cols-2">

                    {selectedScan.indicators.map(
                      (indicator) => (
                        <div
                          key={indicator.label}
                          className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/60 p-3"
                        >

                          <div className="flex min-w-0 items-center gap-2">

                            {indicator.safe ? (
                              <CheckCircle2
                                size={16}
                                className="shrink-0 text-emerald-400"
                              />
                            ) : (
                              <AlertTriangle
                                size={16}
                                className="shrink-0 text-yellow-400"
                              />
                            )}

                            <span className="text-xs text-slate-300">
                              {indicator.label}
                            </span>

                          </div>

                          <span
                            className={`ml-3 text-right text-[11px] font-medium ${
                              indicator.safe
                                ? 'text-emerald-400'
                                : 'text-yellow-400'
                            }`}
                          >
                            {indicator.value}
                          </span>

                        </div>
                      ),
                    )}

                  </div>

                </div>

                {/* Actions */}
                <div className="flex flex-col gap-3 sm:flex-row sm:justify-end">

                  <button
                    type="button"
                    onClick={() =>
                      void generateReport(selectedScan)
                    }
                    disabled={reportGenerating}
                    className="flex items-center justify-center gap-2 rounded-xl bg-cyan-500 px-5 py-3 text-sm font-bold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {reportGenerating ? (
                      <>
                        <Loader2
                          size={17}
                          className="animate-spin"
                        />
                        Generating...
                      </>
                    ) : (
                      <>
                        <FileDown size={17} />
                        Generate Security Report
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => setSelectedScan(null)}
                    className="rounded-xl border border-slate-700 bg-slate-900 px-5 py-3 text-sm font-semibold text-slate-300 transition hover:text-white"
                  >
                    Close
                  </button>

                </div>

              </div>

            </div>
          </div>
        )}

      </div>
    </div>
  )
}

export default ScanHistory