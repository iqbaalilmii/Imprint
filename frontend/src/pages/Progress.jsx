import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import axios from 'axios'

const API_BASE = 'http://localhost:8000'

const PLUGINS = [
  'windows.pslist',
  'windows.pstree',
  'windows.netscan',
  'windows.cmdline',
  'windows.dlllist',
  'windows.malfind',
  'windows.handles',
  'windows.envars',
  'custom.notepad',
  'yara.scan',
  'ioc.extractor',
  'anomaly.scorer',
]

export default function Progress() {
  const { case_id } = useParams()
  const navigate = useNavigate()
  const [status, setStatus] = useState('queued')
  const [progress, setProgress] = useState({ percent: 0, current_plugin: '' })
  const [error, setError] = useState(null)

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const res = await axios.get(`${API_BASE}/api/cases/${case_id}/status`)
        if (!res.data.success) throw new Error(res.data.error)

        const { status, progress } = res.data.data
        setStatus(status)
        setProgress(progress)

        if (status === 'completed') {
          clearInterval(interval)
          setTimeout(() => navigate(`/dashboard/${case_id}`), 1000)
        }

        if (status === 'failed') {
          clearInterval(interval)
          setError('Analisis gagal. Periksa path dump file dan coba lagi.')
        }

      } catch (err) {
        setError(err.message)
        clearInterval(interval)
      }
    }, 3000)

    return () => clearInterval(interval)
  }, [case_id, navigate])

  return (
    <div className="min-h-screen bg-[#07090c] flex items-center justify-center px-4">

      {/* Background grid */}
      <div className="fixed inset-0 bg-[linear-gradient(rgba(0,255,136,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,136,0.03)_1px,transparent_1px)] bg-[size:40px_40px] pointer-events-none" />

      <div className="relative w-full max-w-lg">

        {/* Header */}
        <div className="mb-8">
          <p className="font-mono text-[11px] tracking-[0.2em] text-[#00ff88] uppercase mb-3">
            // Analyzing Memory Dump
          </p>
          <h1 className="text-3xl font-semibold text-white tracking-tight mb-1">
            Analysis in Progress
          </h1>
          <p className="font-mono text-[11px] text-[#4a5568] tracking-widest">
            CASE ID: {case_id}
          </p>
        </div>

        {/* Card */}
        <div className="bg-[#0c0f14] border border-white/[0.08] rounded-lg p-6 space-y-6">

          {/* Progress bar */}
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="font-mono text-[10px] tracking-[0.15em] uppercase text-[#4a5568]">
                Progress
              </span>
              <span className="font-mono text-sm text-[#00ff88]">
                {progress.percent ?? 0}%
              </span>
            </div>
            <div className="w-full h-1.5 bg-[#111520] rounded-full overflow-hidden">
              <div
                className="h-full bg-[#00ff88] rounded-full transition-all duration-500"
                style={{ width: `${progress.percent ?? 0}%` }}
              />
            </div>
          </div>

          {/* Current plugin */}
          <div className="space-y-1.5">
            <p className="font-mono text-[10px] tracking-[0.15em] uppercase text-[#4a5568]">
              Current Task
            </p>
            <p className="font-mono text-sm text-white">
              {status === 'completed'
                ? '✓ Analysis Complete'
                : status === 'queued'
                ? 'Initializing pipeline...'
                : progress.current_plugin || 'Starting...'}
            </p>
          </div>

          {/* Plugin list */}
          <div className="space-y-1.5">
            <p className="font-mono text-[10px] tracking-[0.15em] uppercase text-[#4a5568] mb-2">
              Pipeline
            </p>
            <div className="space-y-1 max-h-52 overflow-y-auto pr-1">
              {PLUGINS.map((plugin, i) => {
                const pluginsDone = Math.floor(((progress.percent ?? 0) / 100) * PLUGINS.length)
                const isDone = i < pluginsDone
                const isCurrent = plugin === progress.current_plugin

                return (
                  <div
                    key={plugin}
                    className={`flex items-center gap-2.5 px-3 py-1.5 rounded font-mono text-xs transition-colors ${
                      isDone
                        ? 'text-[#00ff88] bg-[#003d20]/40'
                        : isCurrent
                        ? 'text-white bg-[#111520] border border-[#00ff88]/20'
                        : 'text-[#2d3748]'
                    }`}
                  >
                    <span className="w-3 text-center">
                      {isDone ? '✓' : isCurrent ? '›' : '·'}
                    </span>
                    {plugin}
                    {isCurrent && (
                      <span className="ml-auto inline-block w-2.5 h-2.5 border border-current border-t-transparent rounded-full animate-spin" />
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-start gap-2 px-3 py-2.5 bg-[#3d0a0d] border border-[#ff4d5a]/30 rounded text-[#ff4d5a] text-sm font-mono">
              <span>⚠</span>
              <span>{error}</span>
            </div>
          )}

          {/* Completed state */}
          {status === 'completed' && (
            <div className="flex items-center gap-2 px-3 py-2.5 bg-[#003d20]/40 border border-[#00ff88]/30 rounded text-[#00ff88] text-sm font-mono">
              <span>✓</span>
              <span>Analysis complete. Redirecting to dashboard...</span>
            </div>
          )}

        </div>

        {/* Footer */}
        <p className="text-center font-mono text-[10px] text-[#2d3748] mt-6 tracking-widest uppercase">
          Bastion Seize · WRECK-IT 7.0
        </p>

      </div>
    </div>
  )
}
