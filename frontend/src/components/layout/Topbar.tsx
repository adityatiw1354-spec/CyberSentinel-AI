import { Bell, CircleHelp } from 'lucide-react'

function Topbar() {
  return (
    <header className="flex h-16 items-center justify-between border-b border-slate-800 bg-slate-950/80 px-6 backdrop-blur">
      <div>
        <p className="text-xs text-slate-500">
          Security Center
        </p>
        <h2 className="text-sm font-semibold text-white">
          CyberSentinel AI
        </h2>
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          aria-label="Help"
          className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-900 hover:text-white"
        >
          <CircleHelp size={19} />
        </button>

        <button
          type="button"
          aria-label="Notifications"
          className="relative rounded-lg p-2 text-slate-400 transition hover:bg-slate-900 hover:text-white"
        >
          <Bell size={19} />

          <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-cyan-400" />
        </button>

        <div className="ml-2 flex items-center gap-3 border-l border-slate-800 pl-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyan-500/10 text-xs font-semibold text-cyan-400">
            U
          </div>

          <div className="hidden sm:block">
            <p className="text-xs font-medium text-white">
              User
            </p>
            <p className="text-[10px] text-slate-500">
              Security Account
            </p>
          </div>
        </div>
      </div>
    </header>
  )
}

export default Topbar