import { useState } from 'react'
import type { FormEvent } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Globe2,
  Info,
  Loader2,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'

type ScanStatus = 'safe' | 'suspicious' | 'threat'

type ScanResult = {
  score: number
  status: ScanStatus
  summary: string
  indicators: {
    label: string
    value: string
    safe: boolean
  }[]
}

function URLScanner() {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')

  const analyzeUrl = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    const trimmedUrl = url.trim()

    if (!trimmedUrl) {
      setError('Please enter a URL to analyze.')
      return
    }

    let parsedUrl: URL

    try {
      parsedUrl = new URL(
        /^https?:\/\//i.test(trimmedUrl)
          ? trimmedUrl
          : `https://${trimmedUrl}`,
      )
    } catch {
      setError('Please enter a valid URL.')
      return
    }

    setError('')
    setScanning(true)
    setResult(null)

    // Temporary frontend simulation.
    // This will be replaced by the FastAPI security-analysis endpoint.
    window.setTimeout(() => {
      const hostname = parsedUrl.hostname.toLowerCase()

      const suspiciousWords = [
        'login',
        'verify',
        'account',
        'secure',
        'update',
        'payment',
      ]

      const suspicious =
        suspiciousWords.some((word) => hostname.includes(word)) ||
        hostname.split('.').length > 3

      const score = suspicious ? 54 : 86

      setResult({
        score,
        status: suspicious ? 'suspicious' : 'safe',
        summary: suspicious
          ? 'The URL contains patterns that deserve additional security verification.'
          : 'No obvious high-risk patterns were detected in this initial assessment.',
        indicators: [
          {
            label: 'HTTPS',
            value: parsedUrl.protocol === 'https:' ? 'Enabled' : 'Not detected',
            safe: parsedUrl.protocol === 'https:',
          },
          {
            label: 'Domain',
            value: hostname,
            safe: true,
          },
          {
            label: 'URL structure',
            value: suspicious ? 'Review recommended' : 'Looks normal',
            safe: !suspicious,
          },
          {
            label: 'Initial risk',
            value: suspicious ? 'Medium' : 'Low',
            safe: !suspicious,
          },
        ],
      })

      setScanning(false)
    }, 1200)
  }

  const statusConfig = {
    safe: {
      label: 'SAFE',
      icon: CheckCircle2,
      text: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
    },
    suspicious: {
      label: 'SUSPICIOUS',
      icon: AlertTriangle,
      text: 'text-amber-400',
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/20',
    },
    threat: {
      label: 'THREAT',
      icon: ShieldAlert,
      text: 'text-red-400',
      bg: 'bg-red-500/10',
      border: 'border-red-500/20',
    },
  }

  const currentStatus = result
    ? statusConfig[result.status]
    : null

  return (
    <div className="min-h-full bg-slate-950 p-6 text-slate-100 md:p-8">
      <div className="mx-auto max-w-5xl">

        {/* Header */}
        <div className="mb-8">
          <div className="mb-2 flex items-center gap-2 text-sm text-cyan-400">
            <ScanSearch size={17} />
            Threat Detection
          </div>

          <h1 className="text-3xl font-bold tracking-tight">
            URL Security Scanner
          </h1>

          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
            Analyze a website URL for suspicious patterns and potential
            security risks.
          </p>
        </div>

        {/* Scanner Card */}
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl shadow-black/10 md:p-8">

          <div className="mb-6 flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400">
              <Globe2 size={22} />
            </div>

            <div>
              <h2 className="font-semibold text-white">
                Analyze a URL
              </h2>

              <p className="text-xs text-slate-500">
                Enter the complete website address below.
              </p>
            </div>
          </div>

          <form onSubmit={analyzeUrl}>
            <div className="flex flex-col gap-3 md:flex-row">
              <div className="relative flex-1">
                <Globe2
                  size={18}
                  className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
                />

                <input
                  type="text"
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  placeholder="https://example.com"
                  disabled={scanning}
                  className="h-12 w-full rounded-xl border border-slate-700 bg-slate-950 pl-11 pr-4 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/10 disabled:opacity-60"
                />
              </div>

              <button
                type="submit"
                disabled={scanning}
                className="flex h-12 items-center justify-center gap-2 rounded-xl bg-cyan-500 px-6 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {scanning ? (
                  <>
                    <Loader2 size={17} className="animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <ScanSearch size={17} />
                    Analyze URL
                  </>
                )}
              </button>
            </div>

            {error && (
              <div className="mt-3 flex items-center gap-2 text-sm text-red-400">
                <Info size={16} />
                {error}
              </div>
            )}
          </form>

          {/* Scanning state */}
          {scanning && (
            <div className="mt-8 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-6">
              <div className="flex items-center gap-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-cyan-500/10 text-cyan-400">
                  <Loader2 size={20} className="animate-spin" />
                </div>

                <div>
                  <p className="text-sm font-medium text-white">
                    Running security analysis
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    Checking URL structure and security indicators...
                  </p>
                </div>
              </div>

              <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-slate-800">
                <div className="h-full w-2/3 animate-pulse rounded-full bg-cyan-500" />
              </div>
            </div>
          )}
        </section>

        {/* Result */}
        {result && currentStatus && (
          <div className="mt-6 space-y-6">

            {/* Result header */}
            <section
              className={`rounded-2xl border ${currentStatus.border} ${currentStatus.bg} p-6 md:p-8`}
            >
              <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">

                <div className="flex items-center gap-4">
                  <div
                    className={`flex h-14 w-14 items-center justify-center rounded-2xl ${currentStatus.bg} ${currentStatus.text}`}
                  >
                    <currentStatus.icon size={28} />
                  </div>

                  <div>
                    <p className="text-xs uppercase tracking-widest text-slate-500">
                      Scan Result
                    </p>

                    <h2 className={`mt-1 text-xl font-bold ${currentStatus.text}`}>
                      {currentStatus.label}
                    </h2>
                  </div>
                </div>

                <div className="text-left md:text-right">
                  <p className="text-xs text-slate-500">
                    Risk Score
                  </p>

                  <p className={`text-4xl font-bold ${currentStatus.text}`}>
                    {result.score}
                    <span className="text-base text-slate-500">
                      /100
                    </span>
                  </p>
                </div>
              </div>

              <p className="mt-6 max-w-3xl text-sm leading-6 text-slate-400">
                {result.summary}
              </p>
            </section>

            {/* Indicators */}
            <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
              <div className="mb-5">
                <h2 className="font-semibold text-white">
                  Security Indicators
                </h2>

                <p className="mt-1 text-xs text-slate-500">
                  Initial checks performed on the submitted URL.
                </p>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                {result.indicators.map((indicator) => (
                  <div
                    key={indicator.label}
                    className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/60 p-4"
                  >
                    <div className="flex items-center gap-3">
                      {indicator.safe ? (
                        <CheckCircle2
                          size={18}
                          className="text-emerald-400"
                        />
                      ) : (
                        <AlertTriangle
                          size={18}
                          className="text-amber-400"
                        />
                      )}

                      <span className="text-sm text-slate-300">
                        {indicator.label}
                      </span>
                    </div>

                    <span className="max-w-[55%] truncate text-right text-xs text-slate-500">
                      {indicator.value}
                    </span>
                  </div>
                ))}
              </div>
            </section>

            {/* AI Insight */}
            <section className="rounded-2xl border border-cyan-500/15 bg-cyan-500/5 p-6">
              <div className="flex gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400">
                  <Sparkles size={20} />
                </div>

                <div>
                  <h2 className="font-semibold text-white">
                    AI Security Insight
                  </h2>

                  <p className="mt-2 text-sm leading-6 text-slate-400">
                    This section will provide an AI-generated explanation
                    of the scan result using the local Qwen model through
                    Ollama once the backend integration is complete.
                  </p>
                </div>
              </div>
            </section>

            {/* Disclaimer */}
            <div className="flex gap-3 rounded-xl border border-slate-800 bg-slate-900/40 p-4">
              <Info
                size={17}
                className="mt-0.5 shrink-0 text-slate-500"
              />

              <p className="text-xs leading-5 text-slate-500">
                This frontend assessment is currently a demonstration
                workflow. It is not a guarantee that a website is safe.
                The production version will use server-side security
                analysis and reputation checks.
              </p>
            </div>
          </div>
        )}

        {/* Empty state */}
        {!result && !scanning && (
          <div className="mt-6 grid gap-4 md:grid-cols-3">
            {[
              {
                icon: Globe2,
                title: 'URL Analysis',
                text: 'Inspect URL structure and security signals.',
              },
              {
                icon: ShieldCheck,
                title: 'Risk Assessment',
                text: 'Receive a clear security risk classification.',
              },
              {
                icon: Sparkles,
                title: 'AI Explanation',
                text: 'Understand security findings in simple language.',
              },
            ].map((item) => {
              const Icon = item.icon

              return (
                <div
                  key={item.title}
                  className="rounded-xl border border-slate-800 bg-slate-900/40 p-5"
                >
                  <Icon size={20} className="text-cyan-400" />

                  <h3 className="mt-4 text-sm font-semibold text-white">
                    {item.title}
                  </h3>

                  <p className="mt-2 text-xs leading-5 text-slate-500">
                    {item.text}
                  </p>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

export default URLScanner