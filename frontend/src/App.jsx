import { Routes, Route } from 'react-router-dom'
import NewCase from './pages/NewCase'
import Progress from './pages/Progress'
import Dashboard from './pages/Dashboard'

function App() {
  return (
    <Routes>
      <Route path="/" element={<NewCase />} />
      <Route path="/progress/:case_id" element={<Progress />} />
      <Route path="/dashboard/:case_id" element={<Dashboard />} />
    </Routes>
  )
}

export default App
