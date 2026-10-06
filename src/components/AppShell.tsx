import { Suspense, useEffect, useMemo, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { NavLink, useLocation, useNavigate, useOutlet } from 'react-router-dom'
import { Command } from 'cmdk'
import { toast } from 'sonner'
import {
  Activity, AlertOctagon, AlertTriangle, ArrowUpRight, Ban, Bell, BookOpen, ChevronDown, Command as CommandIcon,
  FileBarChart2, Fingerprint, Flame, Gauge, LayoutDashboard, ListChecks, LoaderCircle, LogOut, Menu, Moon,
  PanelLeftClose, PanelLeftOpen, Radio, Search, Settings, Shield, ShieldAlert, ShieldCheck, Siren, SlidersHorizontal, Sparkles, Sun,
} from 'lucide-react'
import { useAppStore } from '../store'
import { useLiveState } from '../lib/runtime'
import { signOutUser } from '../lib/auth'
import { formatTime } from '../lib/utils'
import { createIPBlock, isIPCurrentlyBlocked, recordAuditEvent } from '../lib/responseActions'
import type { Alert, AuditLog, Severity } from '../types'
import { Avatar, BrandLogo, Button, Modal, PageSkeleton } from './Ui'
import { ErrorBoundary } from './ErrorBoundary'

const navigation = [
  { label: 'OVERVIEW', items: [{ label: 'Dashboard', path: '/', icon: LayoutDashboard }] },
  { label: 'MONITOR', items: [
    { label: 'Alerts', path: '/alerts', icon: AlertTriangle, badge: 'live' },
    { label: 'Blocked IPs', path: '/blocked-ips', icon: Ban },
    { label: 'Sensors', path: '/sensors', icon: Radio },
  ] },
  { label: 'CONTROL', items: [
    { label: 'Firewall', path: '/firewall', icon: Shield },
    { label: 'Incidents', path: '/incidents', icon: Siren },
    { label: 'Playbooks', path: '/playbooks', icon: ListChecks },
  ] },
  { label: 'INTELLIGENCE', items: [
    { label: 'Reports', path: '/reports', icon: FileBarChart2 },
    { label: 'Audit trail', path: '/audit', icon: Fingerprint, adminOnly: true },
    { label: 'Documentation', path: '/docs', icon: BookOpen },
  ] },
]

const mobileNavigation = [
  { label: 'Home', path: '/', icon: LayoutDashboard },
  { label: 'Alerts', path: '/alerts', icon: AlertTriangle },
  { label: 'Blocked', path: '/blocked-ips', icon: Ban },
  { label: 'Firewall', path: '/firewall', icon: Shield },
  { label: 'Incidents', path: '/incidents', icon: Siren },
]

const pathNames: Record<string, string> = {
  '/': 'Dashboard', '/alerts': 'Alerts', '/blocked-ips': 'Blocked IPs', '/sensors': 'Sensors', '/firewall': 'Firewall',
  '/incidents': 'Incidents', '/playbooks': 'Playbooks', '/reports': 'Reports', '/audit': 'Audit trail', '/settings': 'Settings', '/docs': 'Documentation',
}
const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/
const demoAttackTypes = ['Port Scan', 'SSH Brute Force', 'SQL Injection', 'DDoS', 'Malware C2', 'XSS', 'Ransomware', 'Zero-Day Exploit']
const demoSources = [
  { ip: '185.220.101.45', country: 'Russia', lat: 55.75, lng: 37.62 }, { ip: '103.74.118.23', country: 'China', lat: 31.23, lng: 121.47 },
  { ip: '198.98.57.12', country: 'United States', lat: 39.74, lng: -104.99 }, { ip: '177.54.148.77', country: 'Brazil', lat: -23.55, lng: -46.63 },
  { ip: '45.155.205.233', country: 'India', lat: 19.08, lng: 72.88 }, { ip: '91.240.118.172', country: 'Iran', lat: 35.69, lng: 51.39 },
]

export default function AppShell() {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [notificationOpen, setNotificationOpen] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const [panicSubmitting, setPanicSubmitting] = useState(false)
  const [searchValue, setSearchValue] = useState('')
  const [blockDialogOpen, setBlockDialogOpen] = useState(false)
  const [blockIpValue, setBlockIpValue] = useState('')
  const [blockReason, setBlockReason] = useState('Command palette response')
  const [blockDialogError, setBlockDialogError] = useState('')
  const [blockTargetAlert, setBlockTargetAlert] = useState<Alert | null>(null)
  const [blockSubmitting, setBlockSubmitting] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const outlet = useOutlet()
  const reduceMotion = useReducedMotion()
  const user = useAppStore((state) => state.user)
  const lightMode = useAppStore((state) => state.lightMode)
  const toggleTheme = useAppStore((state) => state.toggleTheme)
  const liveConnected = useLiveState((state) => state.connected)
  const hydrating = useLiveState((state) => state.hydrating)
  const markLiveAlert = useLiveState((state) => state.markLiveAlert)
  const alerts = useAppStore((state) => state.alerts)
  const addAlert = useAppStore((state) => state.addAlert)
  const blockedIPs = useAppStore((state) => state.blockedIPs)
  const notifications = useAppStore((state) => state.notifications)
  const updateManyAlerts = useAppStore((state) => state.updateManyAlerts)
  const markNotificationsRead = useAppStore((state) => state.markNotificationsRead)
  const unread = notifications.filter((item) => !item.read).length
  const activeAlerts = alerts.filter((alert) => alert.status !== 'resolved').length
  const pageTitle = pathNames[location.pathname] || 'Security operations'

  useEffect(() => {
    const goTo: Record<string, string> = { d: '/', a: '/alerts', b: '/blocked-ips', s: '/sensors', p: '/playbooks' }
    let firstKeyAt = 0
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setSearchValue(''); setPaletteOpen((open) => !open); return }
      if (event.key === 'Escape') { setPaletteOpen(false); setSearchValue(''); setNotificationOpen(false); setProfileOpen(false) }
      if (event.target instanceof HTMLElement && ['INPUT', 'TEXTAREA'].includes(event.target.tagName)) return
      if (event.key.toLowerCase() === 'g') { firstKeyAt = Date.now(); return }
      const key = event.key.toLowerCase()
      if (goTo[key] && Date.now() - firstKeyAt < 1000) { navigate(goTo[key]); setMobileOpen(false) }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [navigate])

  const doPanic = async () => {
    if (panicSubmitting) return
    if (user?.role !== 'admin') { toast.error('Administrator access is required for Panic Mode'); return }
    setPanicSubmitting(true)
    const counts = new Map<string, number>()
    alerts.filter((alert) => alert.status !== 'resolved' && alert.status !== 'blocked' && ipv4Pattern.test(alert.sourceIp) && !isIPCurrentlyBlocked(blockedIPs, alert.sourceIp))
      .forEach((alert) => counts.set(alert.sourceIp, (counts.get(alert.sourceIp) || 0) + 1))
    const targets = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)
    const results = await Promise.allSettled(targets.map(([ip, count]) => createIPBlock({
      ip,
      reason: `Panic Mode · ${count} active detections`,
      expiresAt: null,
      user,
    })))
    const newlyBlocked: string[] = []
    const alreadyBlocked: string[] = []
    const failures: Array<{ ip: string; error: string }> = []
    results.forEach((result, index) => {
      const ip = targets[index][0]
      if (result.status === 'rejected') failures.push({ ip, error: result.reason instanceof Error ? result.reason.message : 'Block request failed.' })
      else if (result.value.alreadyBlocked) alreadyBlocked.push(ip)
      else newlyBlocked.push(ip)
    })

    if (newlyBlocked.length) {
      const relatedAlertIds = alerts.filter((alert) => newlyBlocked.includes(alert.sourceIp) && alert.status !== 'resolved' && alert.status !== 'blocked').map((alert) => alert.id)
      if (relatedAlertIds.length) updateManyAlerts(relatedAlertIds, 'blocked')
    }

    const auditEvent: AuditLog = {
      id: `AUD-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`,
      userId: user.id,
      userName: user.fullName,
      action: 'panic_mode.activated',
      target: newlyBlocked.length ? newlyBlocked.join(', ') : 'No eligible attacker IPs',
      metadata: { requested: targets.map(([ip]) => ip), blocked: newlyBlocked, alreadyBlocked, failures },
      createdAt: new Date().toISOString(),
    }
    let auditError = ''
    try { await recordAuditEvent(auditEvent) }
    catch (error) { auditError = error instanceof Error ? error.message : 'Audit database write failed.' }

    if (auditError) toast.error('Panic Mode completed with an audit warning', { description: `${newlyBlocked.length} IPs blocked. The summary audit event could not be saved: ${auditError}` })
    else if (failures.length && !newlyBlocked.length) toast.error('Panic Mode could not block the attacker IPs', { description: failures.map((item) => `${item.ip}: ${item.error}`).join(' · ') })
    else if (!targets.length) toast.info('No eligible attacker IPs were found', { description: 'Unresolved alerts may already be contained or there may be no active source addresses.' })
    else toast.success('Panic Mode activated', { description: `${newlyBlocked.length} attacker IP${newlyBlocked.length === 1 ? '' : 's'} blocked${alreadyBlocked.length ? ` · ${alreadyBlocked.length} already blocked` : ''}${failures.length ? ` · ${failures.length} failed` : ''}.` })
    setPanicSubmitting(false)
  }

  const closePalette = () => { setPaletteOpen(false); setSearchValue('') }
  const openBlockDialog = (target?: Alert) => {
    const typed = searchValue.trim()
    const alert = target || alerts.find((item) => item.sourceIp === typed) || null
    setBlockTargetAlert(alert)
    setBlockIpValue(alert?.sourceIp || (ipv4Pattern.test(typed) ? typed : ''))
    setBlockReason(alert ? `${alert.attackType} · alert ${alert.id}` : 'Command palette response')
    setBlockDialogError('')
    setBlockDialogOpen(true)
    closePalette()
  }
  const closeBlockDialog = () => {
    if (blockSubmitting) return
    setBlockDialogOpen(false)
    setBlockTargetAlert(null)
    setBlockDialogError('')
  }
  const submitBlockIP = async () => {
    if (user?.role !== 'admin') { setBlockDialogError('Administrator access is required to block an IP.'); return }
    const ip = blockIpValue.trim()
    const reason = blockReason.trim()
    if (!ipv4Pattern.test(ip)) { setBlockDialogError('Enter a valid IPv4 address.'); return }
    if (reason.length < 3 || reason.length > 160) { setBlockDialogError('Reason must be between 3 and 160 characters.'); return }
    setBlockSubmitting(true)
    setBlockDialogError('')
    try {
      const sourceAlert = blockTargetAlert?.sourceIp === ip ? blockTargetAlert : undefined
      const result = await createIPBlock({ ip, reason, expiresAt: null, user, sourceAlert })
      if (result.alreadyBlocked) toast.info(`${ip} is already actively blocked`)
      else toast.success(`${ip} blocked`, { description: sourceAlert ? 'The linked alert was marked blocked and the action was audited.' : 'The block list and audit trail were updated.' })
      setBlockDialogOpen(false)
      setBlockTargetAlert(null)
    } catch (error) {
      setBlockDialogError(error instanceof Error ? error.message : 'The block request could not be completed.')
    } finally {
      setBlockSubmitting(false)
    }
  }
  const simulateAlert = () => {
    const source = demoSources[Math.floor(Math.random() * demoSources.length)]
    const attackType = demoAttackTypes[Math.floor(Math.random() * demoAttackTypes.length)]
    const severity: Severity = Math.random() > .78 ? 'critical' : Math.random() > .48 ? 'high' : 'medium'
    const timestamp = new Date().toISOString()
    const destinationIp = `10.24.${Math.ceil(Math.random() * 5)}.${Math.ceil(Math.random() * 220 + 20)}`
    const protocol = attackType === 'DDoS' ? 'UDP' : attackType.includes('SQL') || attackType === 'XSS' ? 'HTTPS' : 'TCP'
    const alert: Alert = {
      id: `ALT-${crypto.randomUUID()}`, timestamp, severity, sourceIp: source.ip, sourceCountry: source.country,
      sourceLat: source.lat, sourceLng: source.lng, destinationIp, protocol, attackType,
      signature: `ET ${attackType.toUpperCase()} simulated command-center detection`, status: 'new',
      rawLog: `[${timestamp}] [**] ${attackType} [**]\\n[src=${source.ip} dst=${destinationIp} proto=${protocol}]\\n[Classification: Attempted ${attackType}]`,
    }
    closePalette()
    markLiveAlert(alert.id)
    addAlert(alert)
    toast.success('Simulated alert created', { description: `${severity.toUpperCase()} · ${attackType} from ${source.ip}` })
  }

  const filteredRoutes = useMemo(() => {
    const query = searchValue.trim().toLowerCase()
    return Object.entries(pathNames).filter(([path, title]) => (user?.role === 'admin' || path !== '/audit') && (!query || `${title} ${path}`.toLowerCase().includes(query)))
  }, [searchValue, user?.role])
  const matchingAlerts = useMemo(() => {
    const query = searchValue.trim().toLowerCase()
    if (!query) return []
    return alerts.filter((alert) => alert.sourceIp.toLowerCase().includes(query) || alert.destinationIp.toLowerCase().includes(query)).slice(0, 8)
  }, [alerts, searchValue])
  const blockCandidates = useMemo(() => [...new Map(matchingAlerts.map((alert) => [alert.sourceIp, alert])).values()].slice(0, 5), [matchingAlerts])
  const typedIp = ipv4Pattern.test(searchValue.trim()) ? searchValue.trim() : ''

  return <div className={`app-frame ${collapsed ? 'sidebar-collapsed' : ''} ${mobileOpen ? 'mobile-sidebar-open' : ''} ${lightMode ? 'light-mode' : ''}`}>
    {mobileOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    <aside className="sidebar">
      <div className="sidebar-brand"><BrandLogo /><button className="collapse-control" aria-label="Toggle sidebar" onClick={() => setCollapsed((value) => !value)}>{collapsed ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}</button></div>
      <div className="workspace-chip"><span className="workspace-mark"><ShieldCheck size={16} /></span><span className="workspace-label"><strong>Acme Security</strong><small>Enterprise workspace</small></span><ChevronDown size={14} className="workspace-chevron" /></div>
      <nav className="side-navigation">
        {navigation.map((group) => <div className="nav-group" key={group.label}>
          <div className="nav-group-label">{group.label}</div>
          {group.items.filter((item) => !('adminOnly' in item) || user?.role === 'admin').map((item) => <NavLink key={item.path} to={item.path} end={item.path === '/'} onClick={() => setMobileOpen(false)} className={({ isActive }) => `side-link ${isActive ? 'side-link-active' : ''}`}>
            <item.icon size={18} strokeWidth={1.8} /><span className="side-link-label">{item.label}</span>{'badge' in item && <span className="nav-live-dot" />}
          </NavLink>)}
        </div>)}
      </nav>
      <div className="sidebar-bottom">
        <div className="system-health"><span className="health-ring"><Activity size={14} /></span><div className="side-link-label"><strong>{liveConnected ? 'All systems nominal' : 'Reconnecting stream'}</strong><small>{liveConnected ? 'Last checked just now' : 'Connection retrying…'}</small></div><span className={liveConnected ? 'pulse-dot' : 'status-dot warning-dot'} /></div>
        <NavLink to="/settings" className={({ isActive }) => `side-link settings-link ${isActive ? 'side-link-active' : ''}`} onClick={() => setMobileOpen(false)}><Settings size={18} /><span className="side-link-label">Settings</span></NavLink>
        <div className="sidebar-user"><Avatar name={user?.fullName || 'Alex Morgan'} online /><span className="side-link-label"><strong>{user?.fullName || 'Alex Morgan'}</strong><small>{user?.role || 'admin'} · SOC team</small></span><button className="sidebar-more" onClick={() => setProfileOpen((value) => !value)} aria-label="Open profile menu"><ChevronDown size={14} /></button></div>
      </div>
    </aside>

    <div className="main-column">
      <header className="topbar">
        <div className="topbar-left"><button className="mobile-menu-button" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={20} /></button><div className="breadcrumb"><span>NetDefender</span><span className="crumb-slash">/</span><strong>{pageTitle}</strong></div></div>
        <div className="topbar-actions">
          <button className="global-search" onClick={() => { setSearchValue(''); setPaletteOpen(true) }}><Search size={15} /><span>Search anything...</span><kbd>⌘ K</kbd></button>
          <span className="topbar-divider" />
          <div className="menu-anchor"><button className="notification-button" onClick={() => { setNotificationOpen((value) => !value); setProfileOpen(false) }} aria-label="Notifications"><Bell size={18} />{unread > 0 && <i>{unread}</i>}</button>
            {notificationOpen && <div className="popover notification-popover"><div className="popover-heading"><div><strong>Notifications</strong><small>{unread} unread</small></div><button onClick={markNotificationsRead}>Mark all read</button></div><div className="notification-list">{notifications.slice(0, 5).map((item) => <div key={item.id} className={`notification-item ${item.read ? '' : 'notification-unread'}`}><span className={`notification-icon n-${item.type}`}>{item.type === 'critical' ? <AlertOctagon size={15} /> : item.type === 'warning' ? <AlertTriangle size={15} /> : <ShieldCheck size={15} />}</span><div><b>{item.title}</b><p>{item.message}</p><time>{formatTime(item.createdAt, true)}</time></div>{!item.read && <i className="notification-new-dot" />}</div>)}</div><button className="popover-footer" onClick={() => { setNotificationOpen(false); navigate('/alerts') }}>View alert queue <ArrowUpRight size={14} /></button></div>}
          </div>
          <div className="menu-anchor"><button className="top-avatar-button" onClick={() => { setProfileOpen((value) => !value); setNotificationOpen(false) }}><Avatar name={user?.fullName || 'Alex Morgan'} /><ChevronDown size={13} /></button>
            {profileOpen && <div className="popover profile-popover"><div className="profile-popover-user"><Avatar name={user?.fullName || 'Alex Morgan'} size="lg" /><div><strong>{user?.fullName || 'Alex Morgan'}</strong><small>{user?.email || 'admin@netdefender.io'}</small></div></div><div className="profile-role"><span>Access level</span><b>{user?.role || 'admin'}</b></div><button className="profile-option" onClick={() => { setProfileOpen(false); navigate('/settings') }}><Settings size={16} /> Account settings</button><button className="profile-option profile-signout" onClick={async () => { await signOutUser(); useAppStore.getState().setUser(null); navigate('/login') }}><LogOut size={16} /> Sign out</button></div>}
          </div>
        </div>
      </header>

      <main className="main-content" aria-busy={hydrating}>
        {hydrating ? <PageSkeleton compact /> : <ErrorBoundary resetKey={location.pathname} scope="page"><AnimatePresence mode="wait" initial={false}><motion.div key={`${location.pathname}${location.search}`} initial={{ opacity: reduceMotion ? 1 : 0, y: reduceMotion ? 0 : 8, filter: reduceMotion ? 'blur(0px)' : 'blur(2px)' }} animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }} exit={{ opacity: reduceMotion ? 1 : 0, y: reduceMotion ? 0 : -4 }} transition={{ duration: reduceMotion ? 0 : .2, ease: 'easeOut' }}><Suspense fallback={<PageSkeleton compact />}>{outlet}</Suspense></motion.div></AnimatePresence></ErrorBoundary>}
      </main>
      <footer className="app-footer"><span>NetDefender <span className="footer-dot">·</span> v2.4.0</span><span><i className="pulse-dot" /> All systems operational</span><span>© 2026 NetDefender Security</span></footer>
    </div>

    <nav className="mobile-bottom-nav" aria-label="Primary mobile navigation">{mobileNavigation.map((item) => <NavLink key={item.path} to={item.path} end={item.path === '/'} onClick={() => setMobileOpen(false)} className={({ isActive }) => `mobile-nav-item ${isActive ? 'mobile-nav-active' : ''}`}><span className="mobile-nav-icon"><item.icon size={18} />{item.path === '/alerts' && activeAlerts > 0 && <i className="mobile-nav-badge">{activeAlerts > 99 ? '99+' : activeAlerts}</i>}</span><small>{item.label}</small></NavLink>)}</nav>

    {user?.role === 'admin' && <button className="panic-button" onClick={() => void doPanic()} disabled={panicSubmitting} aria-label="Panic Mode: block the top five attacker IPs" aria-busy={panicSubmitting} title="Block the top five active attacker IPs"><span className="panic-button-icon">{panicSubmitting ? <LoaderCircle className="spin" size={17} /> : <Flame size={17} />}</span><span>{panicSubmitting ? 'Blocking attackers…' : 'Panic Mode'}</span></button>}

    <Command.Dialog open={paletteOpen} onOpenChange={(isOpen) => { setPaletteOpen(isOpen); if (!isOpen) setSearchValue('') }} label="Global command menu" className="command-dialog">
      <div className="command-shell">
        <div className="command-input-wrap"><Search size={17} /><Command.Input autoFocus placeholder="Search pages, alert IPs, or actions…" value={searchValue} onValueChange={setSearchValue} /><kbd>ESC</kbd></div>
        <Command.List className="command-list">
          <Command.Empty className="command-empty">No matches. Try a page name, IP address, or action.</Command.Empty>
          {filteredRoutes.length > 0 && <Command.Group heading="Navigate to a page">{filteredRoutes.map(([path, title]) => <Command.Item key={path} value={`${title} ${path}`} onSelect={() => { navigate(path); closePalette(); setMobileOpen(false) }}><span className="command-item-icon"><Gauge size={16} /></span><span>{title}</span><kbd>{path === '/' ? 'G D' : ''}</kbd></Command.Item>)}</Command.Group>}
          {matchingAlerts.length > 0 && <><Command.Separator /><Command.Group heading="Search alerts by IP">{matchingAlerts.map((alert) => <Command.Item key={alert.id} value={`${alert.sourceIp} ${alert.destinationIp} ${alert.id} ${alert.attackType}`} onSelect={() => { const search = searchValue.trim() || alert.sourceIp; navigate(`/alerts?search=${encodeURIComponent(search)}`); closePalette(); toast.info('Alert search applied', { description: `Showing alerts that match ${search}.` }) }}><span className="command-item-icon command-alert-icon"><AlertTriangle size={16} /></span><span className="command-alert-result"><b>{alert.sourceIp}<i>→</i>{alert.destinationIp}</b><small>{alert.attackType} · {alert.severity.toUpperCase()} · {alert.id}</small></span></Command.Item>)}</Command.Group></>}
          {user?.role === 'admin' && blockCandidates.length > 0 && <><Command.Separator /><Command.Group heading="Block a matching source">{blockCandidates.map((alert) => <Command.Item key={`block-${alert.sourceIp}`} value={`block ip source ${alert.sourceIp} ${alert.attackType}`} onSelect={() => openBlockDialog(alert)}><span className="command-item-icon command-danger"><Ban size={16} /></span><span className="command-alert-result"><b>Block source IP {alert.sourceIp}</b><small>{isIPCurrentlyBlocked(blockedIPs, alert.sourceIp) ? 'Already active on the block list' : `Confirm before applying · linked alert ${alert.id}`}</small></span></Command.Item>)}</Command.Group></>}
          <Command.Separator />
          <Command.Group heading="Quick actions">
            {user?.role === 'admin' && <Command.Item value="simulate alert create generate" onSelect={simulateAlert}><span className="command-item-icon"><Sparkles size={16} /></span>Simulate Alert</Command.Item>}
            {user?.role === 'admin' && typedIp && !blockCandidates.some((alert) => alert.sourceIp === typedIp) && <Command.Item value={`block ip ${typedIp} address ban`} onSelect={() => openBlockDialog()}><span className="command-item-icon command-danger"><Ban size={16} /></span>Block IP {typedIp}</Command.Item>}
            {user?.role === 'admin' && <Command.Item value="block ip address ban add" onSelect={() => openBlockDialog()}><span className="command-item-icon command-danger"><Ban size={16} /></span>Block IP address…</Command.Item>}
            <Command.Item value={`toggle theme switch to ${lightMode ? 'dark' : 'light'} mode`} onSelect={() => { toggleTheme(); closePalette(); toast.success(`${lightMode ? 'Dark' : 'Light'} theme enabled`) }}><span className="command-item-icon">{lightMode ? <Moon size={16} /> : <Sun size={16} />}</span>Switch to {lightMode ? 'dark' : 'light'} theme</Command.Item>
            <Command.Item value="review new alerts queue" onSelect={() => { navigate('/alerts'); closePalette(); toast.info('Alert queue opened', { description: 'Review incoming detections and response actions.' }) }}><span className="command-item-icon"><ShieldAlert size={16} /></span>Review alerts</Command.Item>
            {user?.role === 'admin' && <Command.Item value="activate panic mode emergency block" onSelect={() => { closePalette(); void doPanic() }}><span className="command-item-icon command-danger"><Flame size={16} /></span>Activate Panic Mode · block top attackers</Command.Item>}
            <Command.Item value="manage firewall rules" onSelect={() => { navigate('/firewall'); closePalette() }}><span className="command-item-icon"><SlidersHorizontal size={16} /></span>Manage firewall rules</Command.Item>
          </Command.Group>
        </Command.List>
        <div className="command-hints"><span><kbd>↑</kbd><kbd>↓</kbd> to navigate</span><span><kbd>↵</kbd> to select</span><span><CommandIcon size={12} /> command menu</span></div>
      </div>
    </Command.Dialog>

    <Modal open={blockDialogOpen} onClose={closeBlockDialog} title="Block IP address?" subtitle="Confirm a network block and write an audit event." size="sm" footer={<><Button variant="ghost" onClick={closeBlockDialog} disabled={blockSubmitting}>Cancel</Button><Button variant="danger" onClick={() => void submitBlockIP()} disabled={blockSubmitting}>{blockSubmitting ? <LoaderCircle className="spin" size={15} /> : <Ban size={15} />} Block IP</Button></>}>
      <div className="form-stack">
        {blockTargetAlert && <div className="form-security-note"><ShieldAlert size={15} /><span>Linked alert <b>{blockTargetAlert.id}</b> · {blockTargetAlert.attackType}. Blocking its source will also update the alert status.</span></div>}
        <label className="form-field"><span>Source IPv4 address <b>*</b></span><input autoFocus inputMode="decimal" maxLength={15} placeholder="203.0.113.42" value={blockIpValue} onChange={(event) => { setBlockIpValue(event.target.value); setBlockDialogError('') }} /></label>
        <label className="form-field"><span>Audit reason <b>*</b></span><input maxLength={160} value={blockReason} onChange={(event) => { setBlockReason(event.target.value); setBlockDialogError('') }} /></label>
        {blockDialogError && <small className="field-error">{blockDialogError}</small>}
      </div>
    </Modal>
  </div>
}
