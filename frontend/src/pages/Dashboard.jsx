import { useState, useEffect, Fragment } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import apiClient from '../api/client'

const SEVERITY_STYLE = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high:     'bg-orange-100 text-orange-700 border-orange-200',
  medium:   'bg-yellow-100 text-yellow-700 border-yellow-200',
  low:      'bg-blue-100 text-blue-700 border-blue-200',
  clean:    'bg-green-100 text-green-700 border-green-200',
}

function SeverityBadge({ severity }) {
  const sev = String(severity || 'clean').toLowerCase()
  return (
    <span className={`inline-flex items-center font-mono text-[10px] px-2 py-0.5 rounded border uppercase tracking-wider ${SEVERITY_STYLE[sev] || SEVERITY_STYLE.clean}`}>
      {sev}
    </span>
  )
}

function ScoreBar({ score }) {
  const color = score >= 85 ? 'bg-red-500' : score >= 70 ? 'bg-orange-400' : score >= 50 ? 'bg-yellow-400' : 'bg-green-400'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-[#f3f4f6] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="font-mono text-xs text-[#6b7280]">{score}</span>
    </div>
  )
}

function PanelHeader({ title, count }) {
  return (
    <div className="flex items-center justify-between px-4 py-2.5 bg-[#f7f8fa] border-b border-[#e5e7eb]">
      <p className="font-mono text-[11px] text-[#6b7280] uppercase tracking-widest">{title}</p>
      {count !== undefined && (
        <span className="font-mono text-[11px] text-[#9ca3af]">{count} entries</span>
      )}
    </div>
  )
}

export default function Dashboard() {
  const { case_id } = useParams()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [results, setResults] = useState([])
  const [summary, setSummary] = useState(null)
  const [expandedPids, setExpandedPids] = useState(new Set())

  useEffect(() => {
    if (!case_id) {
      setError("Invalid Case ID")
      setLoading(false)
      return
    }

    const fetchResults = async () => {
      try {
        setLoading(true)
        setError(null)
        const res = await apiClient.get(`/cases/${case_id}/results`)
        setResults(res.data.results || [])
        setSummary(res.data.summary || null)
      } catch (err) {
        console.error("Error fetching results:", err)
        setError(err.response?.data?.detail || err.response?.data?.error || err.message || 'Failed to fetch results.')
      } finally {
        setLoading(false)
      }
    }

    fetchResults()
  }, [case_id])

  const toggleExpand = (pid) => {
    const next = new Set(expandedPids)
    if (next.has(pid)) {
      next.delete(pid)
    } else {
      next.add(pid)
    }
    setExpandedPids(next)
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-[#f0f2f5] flex flex-col items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <span className="inline-block w-8 h-8 border-4 border-[#1e2433] border-t-transparent rounded-full animate-spin" />
          <p className="font-mono text-sm text-[#4b5563]">Loading analysis results...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen bg-[#f0f2f5] flex flex-col items-center justify-center p-6">
        <div className="w-full max-w-md bg-white border border-red-200 rounded p-6 shadow-sm">
          <p className="font-mono text-xs text-red-600 uppercase tracking-widest mb-1">Error Fetching Results</p>
          <p className="text-sm text-gray-700 mb-4">{error}</p>
          <button
            onClick={() => navigate('/')}
            className="w-full font-mono text-xs text-white bg-[#1e2433] hover:bg-[#2d3748] py-2 rounded transition-colors"
          >
            Back to New Case
          </button>
        </div>
      </div>
    )
  }

  const filteredProcesses = activeTab === 'all'
    ? results
    : results.filter(p => String(p.final_severity || '').toLowerCase() === activeTab.toLowerCase())

  return (
    <div className="min-h-screen bg-[#f0f2f5]">

      {/* Title bar */}
      <div className="bg-[#1e2433] px-5 py-3 flex items-center justify-between sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] tracking-[0.15em] text-[#a0aab8] uppercase">Engram Forensics</span>
          <span className="text-[#3a4458]">·</span>
          <span className="font-mono text-[11px] tracking-[0.15em] text-[#a0aab8] uppercase">Dashboard</span>
          <span className="text-[#3a4458]">·</span>
          <span className="font-mono text-[11px] text-[#4a5568]">{case_id}</span>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/')}
            className="font-mono text-[11px] text-[#a0aab8] hover:text-white transition-colors"
          >
            ← New Case
          </button>
        </div>
      </div>

      <div className="p-5 space-y-4">

        {/* ── Panel 1: Summary ── */}
        <div className="grid grid-cols-4 gap-3">
          
          <div className="bg-white border border-[#d0d5dd] rounded p-4">
            <p className="font-mono text-[10px] text-[#9ca3af] uppercase tracking-widest mb-1">Total Processes</p>
            <p className="text-3xl font-semibold text-[#111827]">{summary?.total_processes ?? 0}</p>
          </div>

          <div className="bg-white border border-[#d0d5dd] rounded p-4">
            <p className="font-mono text-[10px] text-[#9ca3af] uppercase tracking-widest mb-1">Flagged Processes</p>
            <p className="text-3xl font-semibold text-orange-600">{summary?.flagged_count ?? 0}</p>
          </div>

          <div className="bg-white border border-[#d0d5dd] rounded p-4">
            <p className="font-mono text-[10px] text-[#9ca3af] uppercase tracking-widest mb-1">Highest Severity</p>
            <div className="mt-2">
              <SeverityBadge severity={summary?.highest_severity} />
            </div>
          </div>

          <div className="bg-white border border-[#d0d5dd] rounded p-4">
            <p className="font-mono text-[10px] text-[#9ca3af] uppercase tracking-widest mb-1">Severity Breakdown</p>
            <div className="flex flex-wrap gap-1.5 mt-2">
              <span className="px-1.5 py-0.5 text-[9px] font-mono border rounded bg-blue-50 text-blue-700 border-blue-100">
                LOW: {summary?.low_count ?? 0}
              </span>
              <span className="px-1.5 py-0.5 text-[9px] font-mono border rounded bg-yellow-50 text-yellow-700 border-yellow-100">
                MED: {summary?.medium_count ?? 0}
              </span>
              <span className="px-1.5 py-0.5 text-[9px] font-mono border rounded bg-orange-50 text-orange-700 border-orange-100">
                HIGH: {summary?.high_count ?? 0}
              </span>
              <span className="px-1.5 py-0.5 text-[9px] font-mono border rounded bg-red-50 text-red-700 border-red-100">
                CRIT: {summary?.critical_count ?? 0}
              </span>
            </div>
          </div>

        </div>

        {/* ── Panel 2: Process List ── */}
        <div className="bg-white border border-[#d0d5dd] rounded overflow-hidden">
          <PanelHeader title="Process List" count={results.length} />

          {/* Filter tabs */}
          <div className="flex border-b border-[#e5e7eb] px-4 gap-3">
            {['all', 'critical', 'high', 'medium', 'low', 'clean'].map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`font-mono text-[11px] uppercase tracking-wider py-2 border-b-2 transition-colors ${
                  activeTab === tab
                    ? 'border-[#1e2433] text-[#111827]'
                    : 'border-transparent text-[#9ca3af] hover:text-[#6b7280]'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>

          <div className="overflow-auto max-h-[500px]">
            <table className="w-full text-sm text-left">
              <thead>
                <tr className="border-b border-[#e5e7eb]">
                  {['PID', 'Name', 'Severity', 'Score', ''].map((h, i) => (
                    <th 
                      key={i} 
                      className={`font-mono text-[10px] text-[#9ca3af] uppercase tracking-widest px-4 py-3.5 bg-[#fafafa] ${
                        h === '' ? 'text-right' : 'text-left'
                      }`}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#f3f4f6]">
                {filteredProcesses.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center font-mono text-xs text-gray-400 italic">
                      No processes match the selected filter.
                    </td>
                  </tr>
                ) : (
                  filteredProcesses.map((p) => {
                    const isExpanded = expandedPids.has(p.pid)
                    const showML = p.secondary_ml_note?.shown === true
                    
                    return (
                      <Fragment key={p.pid}>
                        <tr className="hover:bg-[#fafafa] transition-colors">
                          <td className="px-4 py-3 font-mono text-xs text-[#6b7280]">
                            {p.pid}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center">
                              <span className="text-xs font-medium text-[#111827]">{p.name}</span>
                              {showML && (
                                <span 
                                  className="inline-flex items-center gap-1 font-mono text-[9px] px-1.5 py-0.5 border rounded uppercase text-[#4b5563] bg-[#f3f4f6] border-[#e5e7eb] cursor-help relative group ml-2"
                                  title={p.secondary_ml_note.disclaimer}
                                >
                                  ML: {p.secondary_ml_note.ml_flagged_as} ({Math.round(p.secondary_ml_note.confidence * 100)}%)
                                  <span className="invisible group-hover:visible absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 w-64 p-2.5 bg-[#1e2433] text-white text-[10px] rounded shadow-lg z-20 normal-case leading-relaxed font-sans text-center">
                                    {p.secondary_ml_note.disclaimer}
                                    <span className="absolute top-full left-1/2 transform -translate-x-1/2 border-4 border-transparent border-t-[#1e2433]"></span>
                                  </span>
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <SeverityBadge severity={p.final_severity} />
                          </td>
                          <td className="px-4 py-3">
                            <ScoreBar score={p.final_score} />
                          </td>
                          <td className="px-4 py-3 text-right">
                            <button
                              onClick={() => toggleExpand(p.pid)}
                              className="font-mono text-[10px] text-[#1e2433] hover:text-white border border-[#d0d5dd] px-3 py-1 rounded bg-white hover:bg-[#1e2433] transition-colors"
                            >
                              {isExpanded ? 'Hide' : 'Detail'}
                            </button>
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr className="bg-[#f9fafb]">
                            <td colSpan={5} className="px-6 py-4 border-b border-[#e5e7eb]">
                              <div className="space-y-4">
                                
                                <div className="text-xs text-gray-700 bg-white p-3.5 border border-gray-200 rounded shadow-sm">
                                  <p className="font-semibold text-gray-800 mb-1">Analyst Summary:</p>
                                  <p className="leading-relaxed">{p.summary_text}</p>
                                </div>

                                <div>
                                  <p className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-wider mb-2">
                                    Primary Severity Factors ({p.primary_reasons?.length ?? 0})
                                  </p>
                                  {p.primary_reasons && p.primary_reasons.length > 0 ? (
                                    <ul className="space-y-1.5">
                                      {p.primary_reasons.map((reason, idx) => (
                                        <li key={idx} className="flex justify-between items-center text-xs text-gray-700 bg-white px-3.5 py-2 border border-gray-200 rounded shadow-sm">
                                          <span className="font-medium">{reason.reason}</span>
                                          <span className="font-mono text-red-600 font-bold bg-red-50 border border-red-100 px-1.5 py-0.5 rounded text-[10px]">
                                            +{reason.points} pts
                                          </span>
                                        </li>
                                      ))}
                                    </ul>
                                  ) : (
                                    <p className="text-xs text-gray-400 italic bg-white p-3 border border-gray-100 rounded">
                                      No suspicious forensic signatures detected.
                                    </p>
                                  )}
                                </div>

                                {showML && (
                                  <div className="p-3.5 bg-gray-50 border border-gray-200 rounded text-xs text-[#4b5563] space-y-1">
                                    <p className="font-semibold text-gray-700">Machine Learning Observation (Secondary):</p>
                                    <p className="font-mono text-[10px]">
                                      Prediction: {p.secondary_ml_note.ml_flagged_as} | Confidence Score: {Math.round(p.secondary_ml_note.confidence * 100)}%
                                    </p>
                                    <p className="text-[11px] text-gray-500 leading-relaxed italic mt-1.5">
                                      {p.secondary_ml_note.disclaimer}
                                    </p>
                                  </div>
                                )}

                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* Bottom bar */}
      <div className="bg-[#f7f8fa] border-t border-[#d0d5dd] px-5 py-2 flex items-center justify-between">
        <span className="font-mono text-[10px] text-[#9ca3af] tracking-widest uppercase">
          Engram v1.0 · Bastion Seize · WRECK-IT 7.0
        </span>
        <span className="font-mono text-[10px] text-[#9ca3af]">
          {summary ? `${summary.critical_count} critical · ${summary.high_count} high · ${summary.medium_count} medium · ${summary.low_count} low` : '—'}
        </span>
      </div>

    </div>
  )
}
