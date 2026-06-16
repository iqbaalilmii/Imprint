import { useParams } from 'react-router-dom'

export default function Dashboard() {
  const { case_id } = useParams()

  return (
    <div className="min-h-screen bg-[#07090c] flex items-center justify-center px-4">
      <div className="text-center">
        <p className="font-mono text-[11px] tracking-[0.2em] text-[#00ff88] uppercase mb-3">
          // Analysis Complete
        </p>
        <h1 className="text-3xl font-semibold text-white tracking-tight mb-2">
          Dashboard
        </h1>
        <p className="font-mono text-[11px] text-[#4a5568] tracking-widest">
          CASE ID: {case_id}
        </p>
        <p className="font-mono text-sm text-[#4a5568] mt-4">
          Coming soon...
        </p>
      </div>
    </div>
  )
}
