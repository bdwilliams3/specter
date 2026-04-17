import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import AuthGuard from './auth/AuthGuard'
import Layout from './components/layout/Layout'
import Dashboard from './pages/Dashboard'
import Inventory from './pages/Inventory'
import Threats from './pages/Threats'
import Rules from './pages/Rules'
import Vulnerabilities from './pages/Vulnerabilities'
import Policies from './pages/Policies'
import Graph from './pages/Graph'
import Settings from './pages/Settings'
import Login from './pages/Login'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/*"
          element={
            <AuthGuard>
              <Layout />
            </AuthGuard>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="inventory" element={<Inventory />} />
          {/* legacy redirect */}
          <Route path="threats" element={<Navigate to="/threats/events" replace />} />
          <Route path="threats/events" element={<Threats />} />
          <Route path="threats/rules" element={<Rules />} />
          <Route path="vulnerabilities" element={<Navigate to="/posture/vulnerabilities" replace />} />
          <Route path="posture/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="posture/policies" element={<Policies />} />
          <Route path="graph" element={<Graph />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
