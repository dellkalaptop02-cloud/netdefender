import { lazy, Suspense } from 'react'
import { BrowserRouter, Navigate, Outlet, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'sonner'
import { ShieldAlert } from 'lucide-react'
import AppShell from './components/AppShell'
const DashboardPage = lazy(() => import('./pages/Dashboard'))
const AlertsPage = lazy(() => import('./pages/Alerts'))
const BlockedIPsPage = lazy(() => import('./pages/BlockedIPs'))
const FirewallPage = lazy(() => import('./pages/Firewall'))
const IncidentsPage = lazy(() => import('./pages/Incidents'))
const SensorsPage = lazy(() => import('./pages/Sensors'))
const PlaybooksPage = lazy(() => import('./pages/Playbooks'))
const ReportsPage = lazy(() => import('./pages/Reports'))
const AuditPage = lazy(() => import('./pages/Audit'))
const SettingsPage = lazy(() => import('./pages/Settings'))
const DocsPage = lazy(() => import('./pages/Docs'))
const LoginPage = lazy(() => import('./pages/Login'))
import { useAppStore } from './store'
import { useApplicationRuntime } from './lib/runtime'
import { BrandLogo, PageSkeleton } from './components/Ui'
import { ErrorBoundary } from './components/ErrorBoundary'
import './styles.css'
import 'leaflet/dist/leaflet.css'

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 30_000, refetchOnWindowFocus: false } } })

function AuthGate({ ready }: { ready: boolean }) {
  const user = useAppStore((state) => state.user)
  if (!ready) return <div className="boot-screen" role="status" aria-live="polite" aria-busy="true">
    <div className="boot-screen-center">
      <div className="boot-logo-stage"><span className="boot-pulse-ring boot-pulse-ring-a" aria-hidden="true" /><span className="boot-pulse-ring boot-pulse-ring-b" aria-hidden="true" /><BrandLogo /></div>
      <p className="boot-tagline">Every packet. Every second. Every threat.</p>
      <div className="boot-status"><span className="boot-spinner" /><span>Establishing secure workspace</span></div>
    </div>
    <div className="boot-screen-caption">NETDEFENDER SECURITY OPERATIONS · SECURE BY DESIGN</div>
  </div>
  if (!user) return <Navigate to="/login" replace />
  return <Outlet />
}

function NotFoundPage() { return <div className="not-found"><ShieldAlert size={25} /><span className="eyebrow">404 · UNKNOWN ROUTE</span><h1>That page isn't on the network.</h1><p>The route may have moved or you may not have permission to access it.</p><button onClick={() => window.location.assign('/')}>Return to dashboard</button></div> }

function RoutedApp() {
  const ready = useApplicationRuntime()
  return <BrowserRouter><ErrorBoundary><Suspense fallback={<PageSkeleton />}><Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route element={<AuthGate ready={ready} />}>
      <Route element={<AppShell />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/blocked-ips" element={<BlockedIPsPage />} />
        <Route path="/firewall" element={<FirewallPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/sensors" element={<SensorsPage />} />
        <Route path="/playbooks" element={<PlaybooksPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/docs" element={<DocsPage />} />
      </Route>
    </Route>
    <Route path="*" element={<NotFoundPage />} />
  </Routes></Suspense></ErrorBoundary></BrowserRouter>
}

export default function App() {
  return <QueryClientProvider client={queryClient}><RoutedApp /><Toaster position="bottom-right" theme="dark" richColors closeButton duration={4200} /></QueryClientProvider>
}
