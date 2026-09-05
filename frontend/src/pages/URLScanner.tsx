import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  FileDown,
  Globe,
  Loader2,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  XCircle,
  Activity,
  Bug,
  SearchCheck,
  Clock3,
  Gauge,
} from 'lucide-react'

type Indicator = {
  label: string
  value: string
  safe: boolean
}

type ScanResult = {
  score: number
  status: 'safe' | 'suspicious' | 'threat'
  risk_level: string
  summary: string
  indicators: Indicator[]
  scanned_at?: string
}

type HistoryItem = ScanResult & {
  id: number
  url: string
  domain: string
}

function URLScanner() {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [historyError, setHistoryError] = useState('')
  const [reportGenerating, setReportGenerating] = useState(false)

  const loadHistory = async () => {
    try {
      setHistoryError('')

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
        throw new Error(data.error || 'Unable to load scan history.')
      }

      setHistory(data.history ?? [])
    } catch (err) {
      setHistoryError(
        err instanceof Error
          ? err.message
          : 'Unable to load scan history.',
      )
    } finally {
      setHistoryLoading(false)
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
      setHistoryError('')

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
    } catch (err) {
      setHistoryError(
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

  const analyzeUrl = async (
    event: FormEvent<HTMLFormElement>,
  ) => {
    event.preventDefault()

    const trimmedUrl = url.trim()

    if (!trimmedUrl) {
      setError('Enter a URL before starting the scan.')
      setResult(null)
      return
    }

    setScanning(true)
    setError('')
    setResult(null)

    try {
      const response = await fetch(
        'http://127.0.0.1:8000/api/scan/url',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            url: trimmedUrl,
          }),
        },
      )

      const data = await response.json()

      if (!response.ok || !data.success) {
        throw new Error(
          data.error || 'Security scan failed.',
        )
      }

      setResult({
        score: data.score,
        status: data.status,
        risk_level: data.risk_level,
        summary: data.summary,
        indicators: data.indicators,
        scanned_at: data.scanned_at,
      })

      await loadHistory()
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to connect to CyberSentinel API.',
      )
    } finally {
      setScanning(false)
    }
  }

  const getIndicator = (label: string) => {
    return result?.indicators.find(
      (indicator) =>
        indicator.label.toLowerCase() === label.toLowerCase(),
    )
  }

  const getStatusIcon = () => {
    if (!result) {
      return <ShieldCheck size={30} />
    }

    if (result.status === 'threat') {
      return <ShieldAlert size={30} />
    }

    if (result.status === 'suspicious') {
      return <AlertTriangle size={30} />
    }

    return <ShieldCheck size={30} />
  }

  const getStatusTitle = () => {
    if (!result) {
      return 'Awaiting Scan'
    }

    if (result.status === 'threat') {
      return 'Threat Detected'
    }

    if (result.status === 'suspicious') {
      return 'Suspicious URL'
    }

    return 'URL Appears Safe'
  }

  const generateReport = async () => {
    if (!result || reportGenerating) {
      return
    }

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
            url,
            score: result.score,
            status: result.status,
            risk_level: result.risk_level,
            summary: result.summary,
            indicators: result.indicators,
            scanned_at: result.scanned_at,
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

  const getStatusClass = () => {
    if (!result) {
      return 'border-slate-800 bg-slate-900/60 text-slate-300'
    }

    if (result.status === 'threat') {
      return 'border-red-500/30 bg-red-500/10 text-red-400'
    }

    if (result.status === 'suspicious') {
      return 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
    }

    return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
  }

  const getScoreLabel = () => {
    if (!result) {
      return 'Waiting'
    }

    if (result.score >= 80) {
      return 'Low Risk'
    }

    if (result.score >= 50) {
      return 'Moderate Risk'
    }

    if (result.score >= 25) {
      return 'High Risk'
    }

    return 'Critical Risk'
  }

  const getScoreWidth = () => {
    if (!result) {
      return '0%'
    }

    return `${Math.max(0, Math.min(100, result.score))}%`
  }

  return (
    <div className="min-h-full bg-slate-950 px-6 py-8 text-slate-100 md:px-10">
      <div className="mx-auto max-w-6xl">

        {/* Header */}
        <div className="mb-8">
          <div className="mb-3 flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-400">
              <ScanSearch size={23} />
            </div>

            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
                CyberSentinel / Security
              </p>

              <h1 className="text-3xl font-bold tracking-tight text-white">
                URL Scanner
              </h1>
            </div>
          </div>

          <p className="max-w-2xl text-sm leading-6 text-slate-400">
            Analyze a URL for suspicious patterns, unsafe protocols,
            unusual domain structures, reputation threats, and other
            security indicators.
          </p>
        </div>

        {/* Scanner Card */}
        <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 shadow-2xl shadow-cyan-950/10">
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-500/70 to-transparent" />

          <div className="p-6 md:p-8">
            <div className="mb-6 flex items-center gap-2 text-xs font-medium uppercase tracking-widest text-slate-500">
              <Terminal size={15} />
              <span>Security Analysis Console</span>
            </div>

            <form onSubmit={analyzeUrl}>
              <label
                htmlFor="url"
                className="mb-2 block text-sm font-medium text-slate-300"
              >
                Target URL
              </label>

              <div className="flex flex-col gap-3 md:flex-row">
                <div className="relative flex-1">
                  <Globe
                    size={18}
                    className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
                  />

                  <input
                    id="url"
                    type="text"
                    value={url}
                    onChange={(event) => setUrl(event.target.value)}
                    placeholder="https://example.com"
                    disabled={scanning}
                    className="h-12 w-full rounded-xl border border-slate-700 bg-slate-950/80 pl-11 pr-4 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-60"
                  />
                </div>

                <button
                  type="submit"
                  disabled={scanning}
                  className="flex h-12 items-center justify-center gap-2 rounded-xl bg-cyan-500 px-7 text-sm font-bold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {scanning ? (
                    <>
                      <Loader2
                        size={18}
                        className="animate-spin"
                      />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <ScanSearch size={18} />
                      Analyze URL
                    </>
                  )}
                </button>
              </div>
            </form>

            {/* Error */}
            {error && (
              <div className="mt-5 flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">
                <XCircle
                  size={19}
                  className="mt-0.5 shrink-0"
                />

                <div>
                  <p className="font-semibold">
                    Scan failed
                  </p>

                  <p className="mt-1 text-red-400/80">
                    {error}
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Scanning State */}
        {scanning && (
          <div className="mt-6 rounded-2xl border border-cyan-500/20 bg-cyan-500/5 p-8 text-center">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400">
              <Loader2
                size={28}
                className="animate-spin"
              />
            </div>

            <h2 className="text-lg font-semibold text-white">
              Running security analysis
            </h2>

            <p className="mt-2 text-sm text-slate-500">
              Checking URL structure, reputation, threat intelligence,
              and security indicators...
            </p>
          </div>
        )}

        {/* Result */}
        {result && !scanning && (
          <div className="mt-6 space-y-6">

            {/* Main Result */}
            <div className="grid gap-6 lg:grid-cols-[280px_1fr]">

              {/* Score */}
              <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
                <div className="mb-5 flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                    Risk Score
                  </span>

                  <span className="text-xs text-slate-600">
                    0 — 100
                  </span>
                </div>

                <div className="flex items-center justify-center py-4">
                  <div className="relative flex h-40 w-40 items-center justify-center rounded-full border-8 border-slate-800">
                    <div className="text-center">
                      <div className="text-5xl font-black text-white">
                        {result.score}
                      </div>

                      <div className="text-xs uppercase tracking-widest text-slate-500">
                        Score
                      </div>
                    </div>
                  </div>
                </div>

                <div
                  className={`mt-4 flex items-center justify-center gap-2 rounded-xl border px-4 py-3 text-sm font-semibold ${getStatusClass()}`}
                >
                  {getStatusIcon()}
                  <span>{result.risk_level} Risk</span>
                </div>

                <div className="mt-4">
                  <div className="mb-2 flex items-center justify-between text-xs">
                    <span className="text-slate-500">
                      Security confidence
                    </span>

                    <span className="font-semibold text-cyan-400">
                      {result.score}%
                    </span>
                  </div>

                  <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                    <div
                      className="h-full rounded-full bg-cyan-500 transition-all duration-700"
                      style={{
                        width: getScoreWidth(),
                      }}
                    />
                  </div>
                </div>
              </div>

              {/* Status */}
              <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
                <div
                  className={`mb-6 flex items-center gap-4 rounded-xl border p-5 ${getStatusClass()}`}
                >
                  <div>
                    {getStatusIcon()}
                  </div>

                  <div>
                    <h2 className="text-xl font-bold">
                      {getStatusTitle()}
                    </h2>

                    <p className="mt-1 text-sm opacity-80">
                      {result.summary}
                    </p>
                  </div>
                </div>

                <div>
                  <p className="mb-2 text-xs font-semibold uppercase tracking-widest text-slate-500">
                    Scanned Target
                  </p>

                  <div className="break-all rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 font-mono text-sm text-cyan-400">
                    {url}
                  </div>
                </div>

                {result.scanned_at && (
                  <div className="mt-4 flex items-center gap-2 text-xs text-slate-500">
                    <Clock3 size={14} />
                    <span>
                      Scanned {formatScanTime(result.scanned_at)}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Threat Intelligence */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
              <div className="mb-6 flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <Activity
                      size={20}
                      className="text-cyan-400"
                    />

                    <h2 className="text-lg font-bold text-white">
                      Threat Intelligence
                    </h2>
                  </div>

                  <p className="mt-1 text-sm text-slate-500">
                    External reputation checks and automated security
                    intelligence collected during this scan.
                  </p>
                </div>

                <span className="hidden rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-3 py-1.5 text-xs font-semibold text-cyan-400 sm:block">
                  LIVE ANALYSIS
                </span>
              </div>

              <div className="grid gap-4 md:grid-cols-3">

                {/* Google Safe Browsing */}
                {(() => {
                  const indicator = getIndicator(
                    'Domain reputation',
                  )

                  return (
                    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5">
                      <div className="mb-4 flex items-center justify-between">
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/20 bg-emerald-500/10 text-emerald-400">
                          <ShieldCheck size={20} />
                        </div>

                        <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600">
                          Reputation
                        </span>
                      </div>

                      <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                        Google Safe Browsing
                      </p>

                      <p
                        className={`mt-2 text-sm font-semibold ${
                          indicator?.safe
                            ? 'text-emerald-400'
                            : 'text-red-400'
                        }`}
                      >
                        {indicator?.value || 'No result available'}
                      </p>

                      <div className="mt-4 flex items-center gap-2 text-xs text-slate-600">
                        <SearchCheck size={13} />
                        <span>
                          {indicator?.safe
                            ? 'No known threat detected'
                            : 'Threat indicator detected'}
                        </span>
                      </div>
                    </div>
                  )
                })()}

                {/* VirusTotal */}
                {(() => {
                  const indicator = getIndicator('VirusTotal')

                  return (
                    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5">
                      <div className="mb-4 flex items-center justify-between">
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-purple-500/20 bg-purple-500/10 text-purple-400">
                          <Bug size={20} />
                        </div>

                        <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600">
                          Multi Engine
                        </span>
                      </div>

                      <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                        VirusTotal
                      </p>

                      <p
                        className={`mt-2 text-sm font-semibold ${
                          indicator?.safe
                            ? 'text-emerald-400'
                            : 'text-red-400'
                        }`}
                      >
                        {indicator?.value || 'No result available'}
                      </p>

                      <div className="mt-4 flex items-center gap-2 text-xs text-slate-600">
                        <Gauge size={13} />
                        <span>
                          Multi-engine URL reputation analysis
                        </span>
                      </div>
                    </div>
                  )
                })()}

                {/* Static Analysis */}
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5">
                  <div className="mb-4 flex items-center justify-between">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/20 bg-cyan-500/10 text-cyan-400">
                      <Terminal size={20} />
                    </div>

                    <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600">
                      Static
                    </span>
                  </div>

                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Static URL Analysis
                  </p>

                  <p className="mt-2 text-sm font-semibold text-cyan-400">
                    {result.indicators.length} checks performed
                  </p>

                  <div className="mt-4 flex items-center gap-2 text-xs text-slate-600">
                    <Activity size={13} />
                    <span>
                      Structure and security pattern analysis
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Assessment Summary */}
            <div className="grid gap-4 md:grid-cols-3">
              <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
                <div className="mb-3 flex items-center gap-2 text-slate-500">
                  <Gauge size={17} />
                  <span className="text-xs font-semibold uppercase tracking-widest">
                    Assessment
                  </span>
                </div>

                <p className="text-lg font-bold text-white">
                  {getScoreLabel()}
                </p>

                <p className="mt-1 text-xs text-slate-600">
                  Based on the combined security score.
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
                <div className="mb-3 flex items-center gap-2 text-slate-500">
                  <SearchCheck size={17} />
                  <span className="text-xs font-semibold uppercase tracking-widest">
                    Indicators
                  </span>
                </div>

                <p className="text-lg font-bold text-white">
                  {result.indicators.filter(
                    (indicator) => !indicator.safe,
                  ).length}{' '}
                  flagged
                </p>

                <p className="mt-1 text-xs text-slate-600">
                  Security checks requiring attention.
                </p>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
                <div className="mb-3 flex items-center gap-2 text-slate-500">
                  <Clock3 size={17} />
                  <span className="text-xs font-semibold uppercase tracking-widest">
                    Scan Status
                  </span>
                </div>

                <p className="text-lg font-bold text-emerald-400">
                  Completed
                </p>

                <p className="mt-1 text-xs text-slate-600">
                  Automated security assessment finished.
                </p>
              </div>
            </div>

            {/* Indicators */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
              <div className="mb-5">
                <h2 className="text-lg font-bold text-white">
                  Security Indicators
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Individual checks performed by CyberSentinel AI.
                </p>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                {result.indicators.map((indicator) => (
                  <div
                    key={indicator.label}
                    className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/60 p-4"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      {indicator.safe ? (
                        <CheckCircle2
                          size={19}
                          className="shrink-0 text-emerald-400"
                        />
                      ) : (
                        <AlertTriangle
                          size={19}
                          className="shrink-0 text-yellow-400"
                        />
                      )}

                      <span className="text-sm text-slate-300">
                        {indicator.label}
                      </span>
                    </div>

                    <span
                      className={`ml-4 text-right text-xs font-medium ${
                        indicator.safe
                          ? 'text-emerald-400'
                          : 'text-yellow-400'
                      }`}
                    >
                      {indicator.value
                        .replace('â', '—')
                        .replace('â€“', '—')
                        .replace('â€”', '—')}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Disclaimer */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 px-5 py-4 text-xs leading-5 text-slate-500">
              This is an initial automated security assessment.
              A low-risk result does not guarantee that a website
              is completely safe.
            </div>

            {/* PDF Report */}
            <button
              type="button"
              onClick={() => void generateReport()}
              disabled={reportGenerating}
              className="flex w-full items-center justify-center gap-2 rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-5 py-3 text-sm font-semibold text-cyan-400 transition hover:bg-cyan-500/15 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {reportGenerating ? (
                <>
                  <Loader2
                    size={18}
                    className="animate-spin"
                  />
                  Generating PDF Report...
                </>
              ) : (
                <>
                  <FileDown size={18} />
                  Generate Security Report
                </>
              )}
            </button>
          </div>
        )}

        {/* Scan History */}
        <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
          <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-widest text-cyan-400">
                Security Archive
              </p>

              <h2 className="mt-1 text-lg font-bold text-white">
                Recent Scan History
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Your latest 20 URL security assessments are stored locally.
              </p>
            </div>

            {history.length > 0 && (
              <button
                type="button"
                onClick={clearHistory}
                className="rounded-lg border border-red-500/20 bg-red-500/5 px-4 py-2 text-xs font-semibold text-red-400 transition hover:bg-red-500/10"
              >
                Clear History
              </button>
            )}
          </div>

          {historyError && (
            <div className="mb-4 rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-400">
              {historyError}
            </div>
          )}

          {historyLoading ? (
            <div className="flex items-center gap-3 rounded-xl border border-slate-800 bg-slate-950/50 p-5 text-sm text-slate-500">
              <Loader2
                size={17}
                className="animate-spin text-cyan-400"
              />
              Loading scan history...
            </div>
          ) : history.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-800 bg-slate-950/40 p-7 text-center">
              <ScanSearch
                size={26}
                className="mx-auto mb-3 text-slate-700"
              />

              <p className="text-sm font-medium text-slate-400">
                No scans yet
              </p>

              <p className="mt-1 text-xs text-slate-600">
                Completed URL scans will appear here automatically.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {history.map((item) => {
                const statusClass =
                  item.status === 'threat'
                    ? 'border-red-500/20 bg-red-500/5 text-red-400'
                    : item.status === 'suspicious'
                      ? 'border-yellow-500/20 bg-yellow-500/5 text-yellow-400'
                      : 'border-emerald-500/20 bg-emerald-500/5 text-emerald-400'

                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setUrl(item.url)

                      setResult({
                        score: item.score,
                        status: item.status,
                        risk_level: item.risk_level,
                        summary: item.summary,
                        indicators: item.indicators,
                        scanned_at: item.scanned_at,
                      })

                      setError('')

                      window.scrollTo({
                        top: 0,
                        behavior: 'smooth',
                      })
                    }}
                    className="w-full rounded-xl border border-slate-800 bg-slate-950/60 p-4 text-left transition hover:border-cyan-500/30 hover:bg-slate-950"
                  >
                    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-mono text-sm text-cyan-400">
                          {item.url}
                        </p>

                        <p className="mt-1 text-xs text-slate-600">
                          {formatScanTime(
                            item.scanned_at ?? '',
                          )}
                        </p>
                      </div>

                      <div className="flex items-center gap-3">
                        <span
                          className={`rounded-lg border px-3 py-1.5 text-xs font-semibold ${statusClass}`}
                        >
                          {item.risk_level} Risk
                        </span>

                        <span className="text-lg font-black text-white">
                          {item.score}
                        </span>
                      </div>
                    </div>
                  </button>
                )
              })}
            </div>
          )}
        </div>

        {/* Empty State */}
        {!result && !scanning && !error && (
          <div className="mt-6 rounded-2xl border border-dashed border-slate-800 bg-slate-950/40 p-12 text-center">
            <ShieldCheck
              size={38}
              className="mx-auto mb-4 text-slate-700"
            />

            <h2 className="text-lg font-semibold text-slate-300">
              Ready for analysis
            </h2>

            <p className="mx-auto mt-2 max-w-md text-sm text-slate-600">
              Enter a website URL above to begin a CyberSentinel
              security assessment.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

export default URLScanner