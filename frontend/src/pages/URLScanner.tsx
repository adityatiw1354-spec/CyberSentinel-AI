import { useState } from 'react'
import type { FormEvent } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Globe,
  Loader2,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  XCircle,
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
}

function URLScanner() {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)

  const analyzeUrl = async (event: FormEvent<HTMLFormElement>) => {
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
      })
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

  const getStatusIcon = () => {
    if (!result) return <ShieldCheck size={30} />

    if (result.status === 'threat') {
      return <ShieldAlert size={30} />
    }

    if (result.status === 'suspicious') {
      return <AlertTriangle size={30} />
    }

    return <ShieldCheck size={30} />
  }

  const getStatusTitle = () => {
    if (!result) return 'Awaiting Scan'

    if (result.status === 'threat') {
      return 'Threat Detected'
    }

    if (result.status === 'suspicious') {
      return 'Suspicious URL'
    }

    return 'URL Appears Safe'
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
            unusual domain structures, and other security indicators.
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
              Checking URL structure and security indicators...
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
                      {indicator.value}
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
          </div>
        )}

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