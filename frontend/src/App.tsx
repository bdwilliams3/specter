import { BrowserRouter, Routes, Route } from 'react-router-dom'
import AuthGuard from './auth/AuthGuard'
import Layout from './components/layout/Layout'
import Dashboard from './pages/Dashboard'
import Inventory from './pages/Inventory'
import Threats from './pages/Threats'
import Vulnerabilities from './pages/Vulnerabilities'
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
          <Route path="threats" element={<Threats />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="graph" element={<Graph />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
