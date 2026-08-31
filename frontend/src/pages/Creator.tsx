import { ShieldCheck, Sparkles, Code2 } from 'lucide-react'

function Creator() {
  return (
    <main className="min-h-full bg-slate-950 px-6 py-10 text-white md:px-10">
      <div className="mx-auto max-w-5xl">

        {/* Header */}
        <div className="mb-10">
          <p className="mb-2 flex items-center gap-2 text-sm font-medium text-cyan-400">
            <Sparkles size={16} />
            CyberSentinel AI
          </p>

          <h1 className="text-4xl font-bold tracking-tight">
            Meet the Creator
          </h1>

          <p className="mt-3 max-w-2xl text-slate-400">
            CyberSentinel AI is built to make cybersecurity analysis
            simpler, smarter, and easier to understand.
          </p>
        </div>

        {/* Creator Card */}
        <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60 shadow-2xl">
          <div className="grid md:grid-cols-[220px_1fr]">

            {/* Avatar */}
            <div className="flex min-h-56 items-center justify-center border-b border-slate-800 bg-gradient-to-br from-cyan-500/10 to-blue-500/5 md:border-b-0 md:border-r">
              <div className="flex h-28 w-28 items-center justify-center rounded-full border border-cyan-400/30 bg-cyan-400/10">
                <Code2 size={48} className="text-cyan-400" />
              </div>
            </div>

            {/* Content */}
            <div className="p-8">
              <p className="text-sm uppercase tracking-widest text-slate-500">
                Creator & Developer
              </p>

              <h2 className="mt-2 text-3xl font-bold">
                CyberSentinel AI Creator
              </h2>

              <p className="mt-4 leading-7 text-slate-400">
                Building a modern AI-powered cybersecurity platform focused
                on URL scanning, password analysis, security insights and
                scan history.
              </p>

              <div className="mt-7 flex flex-wrap gap-3">
                <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 px-4 py-2 text-sm text-slate-300">
                  <ShieldCheck size={17} className="text-cyan-400" />
                  Cybersecurity
                </div>

                <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 px-4 py-2 text-sm text-slate-300">
                  <Sparkles size={17} className="text-cyan-400" />
                  AI Powered
                </div>

                <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 px-4 py-2 text-sm text-slate-300">
                  <Code2 size={17} className="text-cyan-400" />
                  Full Stack
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Project */}
        <section className="mt-6 grid gap-6 md:grid-cols-2">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6">
            <ShieldCheck className="text-cyan-400" size={24} />

            <h3 className="mt-4 text-xl font-semibold">
              About CyberSentinel
            </h3>

            <p className="mt-2 text-sm leading-6 text-slate-400">
              A security-focused platform designed to provide useful
              cybersecurity analysis through a clean and intelligent
              interface.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6">
            <Code2 className="text-cyan-400" size={24} />

            <h3 className="mt-4 text-xl font-semibold">
              Technology
            </h3>

            <p className="mt-2 text-sm leading-6 text-slate-400">
              React, TypeScript, Tailwind CSS and a future backend/API layer
              power the CyberSentinel AI experience.
            </p>
          </div>
        </section>

        {/* Footer */}
        <div className="mt-8 flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/30 px-5 py-4">
          <p className="text-sm text-slate-500">
            Built with curiosity, code and cybersecurity.
          </p>

          <ShieldCheck size={20} className="text-cyan-500" />
        </div>

      </div>
    </main>
  )
}

export default Creator