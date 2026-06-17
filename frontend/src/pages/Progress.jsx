import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import axios from 'axios'

const API_BASE = 'http://localhost:8000'

const PLUGINS = [
  { id: 'windows.pslist',   label: 'windows.pslist',   desc: 'Enumerate running processes' },
  { id: 'windows.pstree',   label: 'windows.pstree',   desc: 'Build process tree' },
  { id: 'windows.netscan',  label: 'windows.netscan',  desc: 'Scan network connections' },
  { id: 'windows.cmdline',  label: 'windows.cmdline',  desc: 'Extract command line arguments' },
  { id: 'windows.dlllist',  label: 'windows.dlllist',  desc: 'List loaded DLL modules' },
  { id: 'windows.malfind',  label: 'windows.malfind',  desc: 'Detect memory injections' },
  { id: 'windows.handles',  label: 'windows.handles',  desc: 'List open handles' },
  { id: 'windows.envars',   label: 'windows.envars',   desc: 'Extract environment variables' },
  { id: 'custom.notepad',   label: 'custom.notepad',   desc: 'Extract Notepad artifacts' },
  { id: 'yara.scan',        label: 'yara.scan',        desc: 'Scan with YARA ruleset' },
  { id: 'ioc.extractor',   label: 'ioc.extractor',    desc: 'Extract & enrich IOCs' },
  { id: 'anomaly.scorer',   label: 'anomaly.scorer',   desc: 'Score process anomalies' },
]

export default function Progress() {
  const { case_id } = useParams()
  const navigate = useNavigate()

  const [status, setStatus] = useState('queued')
  const [percent, setPercent] = useState(0)
  const [currentPlugin, setCurrentPlugin] = useState('')
  const [caseInfo, setCaseInfo] = useState(null)
  const [error, setError] = useState(null)
  const [redirecting, setRedirecting] = useState(false)

  // Ambil info case
  useEffect(() => {
    axios.get(`${API_BASE}/api/cases/${case_id}`)
      .then(res => { if (res.data.success) setCaseInfo(res.data.data) })
      .catch(() => {})
  }, [case_id])

  // Polling status
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const res = await axios.get(`${API_BASE}/api/cases/${case_id}/status`)
        if (!res.data.success) throw new Error(res.data.error)

        const { status, progress } = res.data.data
        setStatus(status)
        setPercent(progress?.percent ?? 0)
        setCurrentPlugin(progress?.current_plugin ?? '')

        if (status === 'completed') {
          clearInterval(interval)
          setRedirecting(true)
          setTimeout(() => navigate(`/dashboard/${case_id}`), 1500)
        }

        if (status === 'failed') {
          clearInterval(interval)
          setError('Analysis failed. Please check the dump file path and try again.')
        }
      } catch (err) {
        setError(err.message)
        clearInterval(interval)
      }
    }, 3000)

    return () => clearInterval(interval)
  }, [case_id, navigate])

  const pluginsDone = Math.floor((percent / 100) * PLUGINS.length)

  const getPluginState = (index) => {
    if (index < pluginsDone) return 'done'
    if (PLUGINS[index].id === currentPlugin) return 'running'
    return 'pending'
  }

  return (
    <div className="min-h-screen bg-[#f0f2f5] flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-2xl bg-white border border-[#d0d5dd] rounded shadow-sm overflow-hidden">

        {/* Title bar */}
        <div className="bg-[#1e2433] px-5 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[11px] tracking-[0.15em] text-[#a0aab8] uppercase">
              Engram Forensics
            </span>
            <span className="text-[#3a4458]">·</span>
            <span className="font-mono text-[11px] tracking-[0.15em] text-[#a0aab8] uppercase">
              Analysis in Progress
            </span>
          </div>
          {/* Live indicator */}
          {status === 'running' && (
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-pulse" />
              <span className="font-mono text-[10px] text-[#00ff88] tracking-widest uppercase">Live</span>
            </div>
          )}
        </div>

        <div className="p-6 space-y-5">

          {/* Case info */}
          <div className="flex items-start justify-between gap-4 pb-4 border-b border-[#e5e7eb]">
            <div>
              <p className="text-[11px] font-mono text-[#9ca3af] uppercase tracking-widest mb-0.5">Case ID</p>
              <p className="font-mono text-sm text-[#111827] font-semibold">{case_id}</p>
            </div>
            {caseInfo && (
              <>
                <div>
                  <p className="text-[11px] font-mono text-[#9ca3af] uppercase tracking-widest mb-0.5">Case Name</p>
                  <p className="text-sm text-[#111827]">{caseInfo.case_name}</p>
                </div>
                <div>
                  <p className="text-[11px] font-mono text-[#9ca3af] uppercase tracking-widest mb-0.5">Analyst</p>
                  <p className="text-sm text-[#111827]">{caseInfo.analyst_name}</p>
                </div>
              </>
            )}
            <div>
              <p className="text-[11px] font-mono text-[#9ca3af] uppercase tracking-widest mb-0.5">Status</p>
              <span className={`inline-flex items-center gap-1 font-mono text-[11px] px-2 py-0.5 rounded-full border ${
                status === 'completed' ? 'bg-green-50 border-green-200 text-green-700' :
                status === 'failed'    ? 'bg-red-50 border-red-200 text-red-600' :
                status === 'running'   ? 'bg-blue-50 border-blue-200 text-blue-700' :
                'bg-gray-50 border-gray-200 text-gray-500'
              }`}>
                {status === 'running' && <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />}
                {status.toUpperCase()}
              </span>
            </div>
          </div>

          {/* Progress bar */}
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <p className="text-[11px] font-mono text-[#6b7280] uppercase tracking-widest">
                {redirecting
                  ? 'Redirecting to dashboard...'
                  : status === 'queued'
                  ? 'Initializing pipeline...'
                  : currentPlugin
                  ? `Running ${currentPlugin}...`
                  : status === 'completed'
                  ? 'Analysis complete'
                  : 'Waiting...'}
              </p>
              <span className="font-mono text-sm font-semibold text-[#111827]">{percent}%</span>
            </div>
            <div className="w-full h-2 bg-[#f3f4f6] rounded-full overflow-hidden border border-[#e5e7eb]">
              <div
                className={`h-full rounded-full transition-all duration-700 ${
                  status === 'completed' ? 'bg-[#16a34a]' :
                  status === 'failed'    ? 'bg-red-500' :
                  'bg-[#1e2433]'
                }`}
                style={{ width: `${percent}%` }}
              />
            </div>
          </div>

          {/* Plugin list */}
          <div className="border border-[#e5e7eb] rounded overflow-hidden">
            <div className="bg-[#f7f8fa] border-b border-[#e5e7eb] px-4 py-2 flex items-center justify-between">
              <p className="text-[11px] font-mono text-[#6b7280] uppercase tracking-widest">
                Analysis Pipeline
              </p>
              <p className="text-[11px] font-mono text-[#9ca3af]">
                {pluginsDone} / {PLUGINS.length} completed
              </p>
            </div>
            <div className="divide-y divide-[#f3f4f6] max-h-64 overflow-y-auto">
              {PLUGINS.map((plugin, i) => {
                const state = getPluginState(i)
                return (
                  <div
                    key={plugin.id}
                    className={`flex items-center gap-3 px-4 py-2.5 transition-colors ${
                      state === 'running' ? 'bg-blue-50' : ''
                    }`}
                  >
                    {/* State icon */}
                    <div className="w-4 h-4 flex items-center justify-center flex-shrink-0">
                      {state === 'done' && (
                        <span className="text-[#16a34a] text-xs font-bold">✓</span>
                      )}
                      {state === 'running' && (
                        <span className="inline-block w-3 h-3 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                      )}
                      {state === 'pending' && (
                        <span className="w-1.5 h-1.5 rounded-full bg-[#d1d5db]" />
                      )}
                    </div>

                    {/* Plugin name */}
                    <span className={`font-mono text-xs flex-shrink-0 ${
                      state === 'done'    ? 'text-[#16a34a]' :
                      state === 'running' ? 'text-blue-700 font-semibold' :
                      'text-[#9ca3af]'
                    }`}>
                      {plugin.label}
                    </span>

                    {/* Description */}
                    <span className="text-[11px] text-[#9ca3af] truncate">
                      — {plugin.desc}
                    </span>

                    {/* Running badge */}
                    {state === 'running' && (
                      <span className="ml-auto font-mono text-[10px] text-blue-600 bg-blue-100 px-2 py-0.5 rounded-full flex-shrink-0">
                        running
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-start gap-2 px-3 py-2.5 bg-red-50 border border-red-200 rounded text-red-600 text-sm">
              <span className="flex-shrink-0">⚠</span>
              <div className="flex-1">
                <p>{error}</p>
                <button
                  onClick={() => navigate('/')}
                  className="mt-2 text-xs underline text-red-500 hover:text-red-700"
                >
                  ← Back to New Case
                </button>
              </div>
            </div>
          )}

          {/* Completed */}
          {redirecting && (
            <div className="flex items-center gap-2 px-3 py-2.5 bg-green-50 border border-green-200 rounded text-green-700 text-sm">
              <span>✓</span>
              <span>Analysis complete. Redirecting to dashboard...</span>
            </div>
          )}

        </div>

        {/* Bottom bar */}
        <div className="bg-[#f7f8fa] border-t border-[#d0d5dd] px-5 py-2 flex items-center justify-between">
          <span className="font-mono text-[10px] text-[#9ca3af] tracking-widest uppercase">
            Engram v1.0 · Bastion Seize · WRECK-IT 7.0
          </span>
          <span className="font-mono text-[10px] text-[#9ca3af]">
            {percent}% complete
          </span>
        </div>

      </div>
    </div>
  )
}
