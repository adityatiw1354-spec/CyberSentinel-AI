import {
  BrowserRouter,
  Routes,
  Route,
} from 'react-router-dom'

import AppLayout from '../components/layout/AppLayout'

import Landing from '../pages/Landing'
import Dashboard from '../pages/Dashboard'
import PasswordAnalyzer from '../pages/PasswordAnalyzer'
import URLScanner from '../pages/URLScanner'
import ScanHistory from '../pages/ScanHistory'
import Profile from '../pages/Profile'
import Settings from '../pages/Settings'
import Creator from '../pages/Creator'

function AppRoutes() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public */}
        <Route path="/" element={<Landing />} />

        {/* Application */}
        <Route element={<AppLayout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/creator" element={<Creator />} />
          <Route
            path="/password-analyzer"
            element={<PasswordAnalyzer />}
          />
          <Route path="/url-scanner" element={<URLScanner />} />
          <Route path="/scan-history" element={<ScanHistory />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default AppRoutes