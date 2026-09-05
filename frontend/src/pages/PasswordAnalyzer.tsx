import { useState } from 'react'
import type { FormEvent } from 'react'
import { apiFetch } from '../lib/api'
import {
  AlertTriangle,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  LockKeyhole,
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

type BreachStatus =
  | 'compromised'
  | 'not_found'
  | 'unavailable'

type AnalysisResult = {
  score: number
  strength: string
  status: 'strong' | 'moderate' | 'weak'
  indicators: Indicator[]
  recommendations: string[]
  breachStatus: BreachStatus
  breachCount: number
}

function PasswordAnalyzer() {
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<AnalysisResult | null>(null)

  const analyzePassword = async (
    event: FormEvent<HTMLFormElement>,
  ) => {
    event.preventDefault()

    if (!password) {
      setError('Enter a password before starting the analysis.')
      setResult(null)
      return
    }

    setScanning(true)
    setError('')
    setResult(null)

    try {
      const response = await apiFetch('/api/analyze/password', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            password,
          }),
        },
      )

      const data = await response.json()

      if (!response.ok || !data.success) {
        throw new Error(
          data.error || 'Password analysis failed.',
        )
      }

      /*
       * BACKEND RESPONSE:
       *
       * breach_status:
       *   "checked"
       *   "unavailable"
       *   "timeout"
       *
       * breach_count:
       *   > 0 = compromised
       *   0   = not found
       *
       * Frontend converts these values into the UI states
       * used by this component.
       */

      const breachCount = Number(data.breach_count) || 0
      const backendBreachStatus = data.breach_status

      let breachStatus: BreachStatus

      if (
        backendBreachStatus === 'checked' &&
        breachCount > 0
      ) {
        breachStatus = 'compromised'
      } else if (
        backendBreachStatus === 'checked' &&
        breachCount === 0
      ) {
        breachStatus = 'not_found'
      } else {
        breachStatus = 'unavailable'
      }

      setResult({
        score: Number(data.score) || 0,
        strength: data.strength || 'Unknown',
        status: data.status || 'weak',
        indicators: Array.isArray(data.indicators)
          ? data.indicators
          : [],
        recommendations: Array.isArray(data.recommendations)
          ? data.recommendations
          : [],
        breachStatus,
        breachCount,
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

  const getStrengthColor = () => {
    if (!result) return 'bg-slate-700'

    if (result.status === 'strong') {
      return 'bg-emerald-400'
    }

    if (result.status === 'moderate') {
      return 'bg-yellow-400'
    }

    return 'bg-red-400'
  }

  const getStrengthTextColor = () => {
    if (!result) return 'text-slate-400'

    if (result.status === 'strong') {
      return 'text-emerald-400'
    }

    if (result.status === 'moderate') {
      return 'text-yellow-400'
    }

    return 'text-red-400'
  }

  const getStatusIcon = () => {
    if (!result) {
      return <ShieldCheck size={30} />
    }

    if (result.status === 'strong') {
      return <ShieldCheck size={30} />
    }

    if (result.status === 'moderate') {
      return <AlertTriangle size={30} />
    }

    return <ShieldAlert size={30} />
  }

  return (
    <div className="min-h-full bg-slate-950 px-6 py-8 text-slate-100 md:px-10">
      <div className="mx-auto max-w-6xl">

        {/* Header */}
        <div className="mb-8">
          <div className="mb-3 flex items-center gap-3">

            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-400">
              <KeyRound size={23} />
            </div>

            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
                CyberSentinel / Security
              </p>

              <h1 className="text-3xl font-bold tracking-tight text-white">
                Password Analyzer
              </h1>
            </div>

          </div>

          <p className="max-w-2xl text-sm leading-6 text-slate-400">
            Analyze password strength, detect security weaknesses,
            and check whether the password appears in known breach data.
          </p>
        </div>

        {/* Analyzer Card */}
        <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 shadow-2xl shadow-cyan-950/10">

          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-500/70 to-transparent" />

          <div className="p-6 md:p-8">

            <div className="mb-6 flex items-center gap-2 text-xs font-medium uppercase tracking-widest text-slate-500">
              <Terminal size={15} />
              <span>Password Security Console</span>
            </div>

            <form onSubmit={analyzePassword}>

              <label
                htmlFor="password"
                className="mb-2 block text-sm font-medium text-slate-300"
              >
                Password
              </label>

              <div className="flex flex-col gap-3 md:flex-row">

                <div className="relative flex-1">

                  <LockKeyhole
                    size={18}
                    className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
                  />

                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(event) =>
                      setPassword(event.target.value)
                    }
                    placeholder="Enter password to analyze"
                    disabled={scanning}
                    className="h-12 w-full rounded-xl border border-slate-700 bg-slate-950/80 pl-11 pr-12 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-60"
                  />

                  <button
                    type="button"
                    onClick={() =>
                      setShowPassword((current) => !current)
                    }
                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg p-2 text-slate-500 transition hover:bg-slate-800 hover:text-cyan-400"
                    aria-label={
                      showPassword
                        ? 'Hide password'
                        : 'Show password'
                    }
                  >
                    {showPassword ? (
                      <EyeOff size={18} />
                    ) : (
                      <Eye size={18} />
                    )}
                  </button>

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
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={18} />
                      Analyze Password
                    </>
                  )}
                </button>

              </div>
            </form>

            {/* Privacy note */}
            <div className="mt-5 flex items-center gap-2 text-xs text-slate-600">
              <ShieldCheck size={14} />

              <span>
                Passwords are analyzed for this request and are not
                displayed in the results.
              </span>
            </div>

            {/* Error */}
            {error && (
              <div className="mt-5 flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">

                <XCircle
                  size={19}
                  className="mt-0.5 shrink-0"
                />

                <div>

                  <p className="font-semibold">
                    Analysis failed
                  </p>

                  <p className="mt-1 text-red-400/80">
                    {error}
                  </p>

                </div>

              </div>
            )}

          </div>
        </div>

        {/* Loading */}
        {scanning && (
          <div className="mt-6 rounded-2xl border border-cyan-500/20 bg-cyan-500/5 p-8 text-center">

            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400">
              <Loader2
                size={28}
                className="animate-spin"
              />
            </div>

            <h2 className="text-lg font-semibold text-white">
              Running password analysis
            </h2>

            <p className="mt-2 text-sm text-slate-500">
              Checking strength, security indicators and breach intelligence...
            </p>

          </div>
        )}

        {/* Results */}
        {result && !scanning && (
          <div className="mt-6 space-y-6">

            {/* Score + Strength */}
            <div className="grid gap-6 lg:grid-cols-[280px_1fr]">

              {/* Score */}
              <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">

                <div className="mb-5 flex items-center justify-between">

                  <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                    Security Score
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

                <div className="mt-4">

                  <div className="mb-2 flex justify-between text-xs">

                    <span className="text-slate-500">
                      Strength
                    </span>

                    <span
                      className={`font-semibold ${getStrengthTextColor()}`}
                    >
                      {result.strength}
                    </span>

                  </div>

                  <div className="h-2 overflow-hidden rounded-full bg-slate-800">

                    <div
                      className={`h-full rounded-full transition-all duration-700 ${getStrengthColor()}`}
                      style={{
                        width: `${Math.min(result.score, 100)}%`,
                      }}
                    />

                  </div>

                </div>

              </div>

              {/* Strength Status */}
              <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">

                <div
                  className={`flex items-center gap-4 rounded-xl border p-5 ${
                    result.status === 'strong'
                      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                      : result.status === 'moderate'
                        ? 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
                        : 'border-red-500/30 bg-red-500/10 text-red-400'
                  }`}
                >

                  {getStatusIcon()}

                  <div>

                    <h2 className="text-xl font-bold">
                      {result.strength} Password
                    </h2>

                    <p className="mt-1 text-sm opacity-80">
                      {result.status === 'strong'
                        ? 'Good password structure detected.'
                        : result.status === 'moderate'
                          ? 'Some improvements are recommended.'
                          : 'This password needs significant improvement.'}
                    </p>

                  </div>

                </div>

                <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/70 p-5">

                  <div className="flex items-center gap-3">

                    <ShieldCheck
                      size={20}
                      className="text-cyan-400"
                    />

                    <div>

                      <p className="text-sm font-semibold text-white">
                        Security assessment
                      </p>

                      <p className="mt-1 text-xs leading-5 text-slate-500">
                        Score is based on length, character diversity,
                        weak patterns, repeated characters and breach intelligence.
                      </p>

                    </div>

                  </div>

                </div>

              </div>

            </div>

            {/* Breach Intelligence */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">

              <div className="mb-5 flex items-center gap-3">

                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-500/10 text-red-400">
                  <ShieldAlert size={21} />
                </div>

                <div>

                  <h2 className="text-lg font-bold text-white">
                    Breach Intelligence
                  </h2>

                  <p className="mt-1 text-sm text-slate-500">
                    Checking against known compromised-password data.
                  </p>

                </div>

              </div>

              {/* COMPROMISED */}
              {result.breachStatus === 'compromised' && (
                <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-5">

                  <div className="flex items-start gap-4">

                    <ShieldAlert
                      size={25}
                      className="mt-0.5 shrink-0 text-red-400"
                    />

                    <div>

                      <p className="font-bold text-red-400">
                        Compromised Password Detected
                      </p>

                      <p className="mt-2 text-sm leading-6 text-slate-300">
                        This password was found{' '}
                        <span className="font-bold text-red-400">
                          {result.breachCount.toLocaleString()}
                        </span>{' '}
                        times in known breach data.
                      </p>

                      <p className="mt-3 text-xs leading-5 text-red-300/80">
                        Do not use this password. Choose a completely
                        unique replacement.
                      </p>

                    </div>

                  </div>

                </div>
              )}

              {/* NOT FOUND */}
              {result.breachStatus === 'not_found' && (
                <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-5">

                  <div className="flex items-start gap-4">

                    <CheckCircle2
                      size={25}
                      className="mt-0.5 shrink-0 text-emerald-400"
                    />

                    <div>

                      <p className="font-bold text-emerald-400">
                        No Known Breach Match
                      </p>

                      <p className="mt-2 text-sm leading-6 text-slate-300">
                        This password was not found in the checked
                        compromised-password dataset.
                      </p>

                      <p className="mt-3 text-xs leading-5 text-emerald-300/70">
                        This does not guarantee that the password has
                        never been exposed elsewhere.
                      </p>

                    </div>

                  </div>

                </div>
              )}

              {/* UNAVAILABLE */}
              {result.breachStatus === 'unavailable' && (
                <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/10 p-5">

                  <div className="flex items-start gap-4">

                    <AlertTriangle
                      size={25}
                      className="mt-0.5 shrink-0 text-yellow-400"
                    />

                    <div>

                      <p className="font-bold text-yellow-400">
                        Breach Check Unavailable
                      </p>

                      <p className="mt-2 text-sm leading-6 text-slate-300">
                        Password strength was analyzed, but the external
                        breach verification could not be completed.
                      </p>

                    </div>

                  </div>

                </div>
              )}

            </div>

            {/* Indicators */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">

              <div className="mb-5">

                <h2 className="text-lg font-bold text-white">
                  Security Indicators
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Individual checks performed during the analysis.
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

            {/* Recommendations */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">

              <div className="mb-5">

                <h2 className="text-lg font-bold text-white">
                  Security Recommendations
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Steps that can improve password security.
                </p>

              </div>

              <div className="space-y-3">

                {result.recommendations.map(
                  (recommendation, index) => (
                    <div
                      key={`${recommendation}-${index}`}
                      className="flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-950/60 p-4"
                    >

                      <div className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-cyan-500/10 text-xs font-bold text-cyan-400">
                        {index + 1}
                      </div>

                      <p className="text-sm leading-6 text-slate-300">
                        {recommendation}
                      </p>

                    </div>
                  ),
                )}

              </div>

            </div>

            {/* Warning */}
            <div className="flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/40 px-5 py-4 text-xs leading-5 text-slate-500">

              <AlertTriangle
                size={16}
                className="mt-0.5 shrink-0"
              />

              <p>
                A strong score does not guarantee that a password
                has never been exposed. Breach intelligence only
                reflects the dataset available to the analyzer.
              </p>

            </div>

          </div>
        )}

        {/* Empty State */}
        {!result && !scanning && !error && (
          <div className="mt-6 rounded-2xl border border-dashed border-slate-800 bg-slate-950/40 p-12 text-center">

            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-slate-800 bg-slate-900 text-slate-700">
              <KeyRound size={25} />
            </div>

            <h2 className="text-lg font-semibold text-slate-300">
              Ready for analysis
            </h2>

            <p className="mx-auto mt-2 max-w-md text-sm text-slate-600">
              Enter a password above to run a CyberSentinel
              security assessment and breach intelligence check.
            </p>

          </div>
        )}

      </div>
    </div>
  )
}

export default PasswordAnalyzer