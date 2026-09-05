import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'

import AppLayout from '../components/layout/AppLayout'

import Landing from '../pages/Landing'
import Login from '../pages/Login'
import Register from '../pages/Register'

import Dashboard from '../pages/Dashboard'
import PasswordAnalyzer from '../pages/PasswordAnalyzer'
import URLScanner from '../pages/URLScanner'
import ScanHistory from '../pages/ScanHistory'
import Profile from '../pages/Profile'
import Settings from '../pages/Settings'
import Creator from '../pages/Creator'

import ProtectedRoute from './ProtectedRoute'

function AppRoutes() {
  return (
    <BrowserRouter>
      <Routes>

        {/* PUBLIC ROUTES */}
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* PROTECTED ROUTES */}
        <Route element={<ProtectedRoute />}>
          <Route element={<AppLayout />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/url-scanner" element={<URLScanner />} />
            <Route
              path="/password-analyzer"
              element={<PasswordAnalyzer />}
            />
            <Route path="/scan-history" element={<ScanHistory />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/creator" element={<Creator />} />
          </Route>
        </Route>

        {/* FALLBACK */}
        <Route path="*" element={<Navigate to="/" replace />} />

      </Routes>
    </BrowserRouter>
  )
}

export default AppRoutes