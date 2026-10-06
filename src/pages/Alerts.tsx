import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import Papa from 'papaparse'
import { toast } from 'sonner'
import { Activity, AlertTriangle, Ban, Check, ChevronDown, ChevronLeft, ChevronRight, Download, Filter, Search, ShieldAlert, SlidersHorizontal, Sparkles, X } from 'lucide-react'
import { useAppStore } from '../store'
import { useLiveState } from '../lib/runtime'
import { createIPBlock, isIPCurrentlyBlocked } from '../lib/responseActions'
import { Button, EmptyState, IconButton, LiveIndicator, PageHeader, SeverityBadge, StatusBadge } from '../components/Ui'
import AlertDrawer from '../components/AlertDrawer'
import { formatTime, timeAgo, downloadText, sanitizeCsvRows } from '../lib/utils'
import type { Alert, Severity } from '../types'

const randomSources = [
  { ip: '185.220.101.45', country: 'Russia', lat: 55.75, lng: 37.62 }, { ip: '103.74.118.23', country: 'China', lat: 31.23, lng: 121.47 },
  { ip: '198.98.57.12', country: 'United States', lat: 39.74, lng: -104.99 }, { ip: '177.54.148.77', country: 'Brazil', lat: -23.55, lng: -46.63 },
  { ip: '45.155.205.233', country: 'India', lat: 19.08, lng: 72.88 }, { ip: '91.240.118.172', country: 'Iran', lat: 35.69, lng: 51.39 },
]
const attackKinds = ['Port Scan', 'SSH Brute Force', 'SQL Injection', 'DDoS', 'Malware C2', 'XSS', 'Ransomware', 'Zero-Day Exploit']
const signatures = ['ET SCAN Potential service discovery scan', 'ET POLICY SSH brute force attempt', 'ET WEB_SERVER SQL injection attempt', 'ET DOS Possible UDP amplification attack', 'ET TROJAN C2 beacon detected']

export default function AlertsPage() {
  const alerts = useAppStore((state) => state.alerts)
  const blocks = useAppStore((state) => state.blockedIPs)
  const user = useAppStore((state) => state.user)
  const liveConnected = useLiveState((state) => state.connected)
  const markLiveAlert = useLiveState((state) => state.markLiveAlert)
  const addAlert = useAppStore((state) => state.addAlert)
  const updateAlert = useAppStore((state) => state.updateAlert)
  const updateManyAlerts = useAppStore((state) => state.updateManyAlerts)
  const addBlockedIP = useAppStore((state) => state.addBlockedIP)
  const addAuditLog = useAppStore((state) => state.addAuditLog)
  const [severity, setSeverity] = useState('all')
  const [status, setStatus] = useState('all')
  const [searchParams, setSearchParams] = useSearchParams()
  const [query, setQuery] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [page, setPage] = useState(1)
  const [sortBy, setSortBy] = useState<'timestamp' | 'severity'>('timestamp')
  const [sortDesc, setSortDesc] = useState(true)
  const [selected, setSelected] = useState<string[]>([])
  const [drawerAlert, setDrawerAlert] = useState<Alert | null>(null)
  const [blockingAlertId, setBlockingAlertId] = useState<string | null>(null)
  const pageSize = 25
  const deepLinkSearch = searchParams.get('search')

  useEffect(() => {
    if (!deepLinkSearch) return
    setQuery(deepLinkSearch)
    setPage(1)
    const next = new URLSearchParams(searchParams)
    next.delete('search')
    setSearchParams(next, { replace: true })
  }, [deepLinkSearch, searchParams, setSearchParams])

  const filtered = useMemo(() => alerts.filter((item) => {
    const qMatch = !query || [item.sourceIp, item.destinationIp, item.attackType, item.signature, item.sourceCountry].some((value) => value.toLowerCase().includes(query.toLowerCase()))
    const day = item.timestamp.slice(0, 10)
    return qMatch && (severity === 'all' || item.severity === severity) && (status === 'all' || item.status === status) && (!dateFrom || day >= dateFrom) && (!dateTo || day <= dateTo)
  }).sort((a, b) => {
    if (sortBy === 'severity') {
      const scale: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }
      return (scale[a.severity] - scale[b.severity]) * (sortDesc ? -1 : 1)
    }
    return (new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()) * (sortDesc ? -1 : 1)
  }), [alerts, query, severity, status, dateFrom, dateTo, sortBy, sortDesc])
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize))
  const rows = filtered.slice((page - 1) * pageSize, page * pageSize)
  const allPageSelected = rows.length > 0 && rows.every((item) => selected.includes(item.id))

  const simulateAlert = () => {
    const source = randomSources[Math.floor(Math.random() * randomSources.length)]
    const attackType = attackKinds[Math.floor(Math.random() * attackKinds.length)]
    const severityValue: Severity = Math.random() > 0.68 ? 'critical' : Math.random() > 0.5 ? 'high' : 'medium'
    const timestamp = new Date().toISOString()
    const newAlert: Alert = {
      id: `ALT-${String(Date.now()).slice(-6)}`, timestamp, severity: severityValue, sourceIp: source.ip, sourceCountry: source.country,
      sourceLat: source.lat, sourceLng: source.lng, destinationIp: `10.24.2.${Math.floor(Math.random() * 200 + 20)}`, protocol: ['TCP', 'UDP', 'HTTPS'][Math.floor(Math.random() * 3)],
      attackType, signature: signatures[Math.floor(Math.random() * signatures.length)], status: 'new',
      rawLog: `[${timestamp}] [**] ${attackType} [**]\n[src=${source.ip} dst=10.24.2.40 proto=TCP]\n[Classification: Attempted ${attackType}] [Priority: ${severityValue === 'critical' ? 1 : 2}]`,
    }
    markLiveAlert(newAlert.id); addAlert(newAlert); setPage(1); toast.success('Demo alert injected', { description: `${severityValue.toUpperCase()} · ${attackType} from ${source.country}` })
  }

  const blockAlert = async (alert: Alert) => {
    if (user?.role !== 'admin' || blockingAlertId) return
    if (isIPCurrentlyBlocked(blocks, alert.sourceIp)) { toast.info('IP is already on the block list'); return }
    setBlockingAlertId(alert.id)
    try {
      const result = await createIPBlock({ ip: alert.sourceIp, reason: `${alert.attackType} · alert ${alert.id}`, expiresAt: null, user, sourceAlert: alert })
      if (result.alreadyBlocked) { toast.info('IP is already on the block list'); return }
      toast.success(`${alert.sourceIp} blocked`, { description: 'The alert was marked blocked and the action was recorded in the audit log.' })
    } catch (error) {
      toast.error('Could not block source IP', { description: error instanceof Error ? error.message : 'Try again or contact your administrator.' })
    } finally { setBlockingAlertId(null) }
  }

  const toggleSelect = (id: string) => setSelected((items) => items.includes(id) ? items.filter((item) => item !== id) : [...items, id])
  const togglePageSelect = () => setSelected((items) => allPageSelected ? items.filter((id) => !rows.some((row) => row.id === id)) : [...new Set([...items, ...rows.map((row) => row.id)])])

  const bulkResolve = () => {
    updateManyAlerts(selected, 'resolved'); toast.success(`${selected.length} alert${selected.length === 1 ? '' : 's'} resolved`); setSelected([])
  }
  const bulkBlock = () => {
    const targetRows = alerts.filter((item) => selected.includes(item.id))
    let count = 0
    targetRows.forEach((item, index) => {
      if (!blocks.some((entry) => entry.ip === item.sourceIp && entry.isActive)) {
        addBlockedIP({ id: `BLK-${Date.now()}-${index}`, ip: item.sourceIp, reason: `Bulk response · ${item.attackType}`, blockedBy: user?.fullName || 'SOC Operator', blockedAt: new Date().toISOString(), expiresAt: null, isActive: true }); count++
      }
      updateAlert(item.id, { status: 'blocked' })
    })
    if (targetRows.length) addAuditLog({ id: `AUD-${Date.now()}`, userId: user?.id || 'demo', userName: user?.fullName || 'SOC Operator', action: 'bulk_block.executed', target: `${count} IPs`, metadata: { alertIds: selected }, createdAt: new Date().toISOString() })
    toast.success(`${count} source IP${count === 1 ? '' : 's'} blocked`); setSelected([])
  }
  const exportCsv = () => {
    const exportRows = (selected.length ? alerts.filter((item) => selected.includes(item.id)) : filtered).map((item) => ({ id: item.id, timestamp: item.timestamp, severity: item.severity, source_ip: item.sourceIp, source_country: item.sourceCountry, destination_ip: item.destinationIp, protocol: item.protocol, attack_type: item.attackType, status: item.status, signature: item.signature }))
    downloadText(`netdefender-alerts-${new Date().toISOString().slice(0, 10)}.csv`, Papa.unparse(sanitizeCsvRows(exportRows)), 'text/csv;charset=utf-8')
    toast.success(`${exportRows.length} alerts exported to CSV`)
  }

  const changeSort = (value: 'timestamp' | 'severity') => { if (value === sortBy) setSortDesc((current) => !current); else { setSortBy(value); setSortDesc(true) } }

  return <div className="page">
    <PageHeader eyebrow="THREAT MONITORING" title="Alert queue" description="Review, investigate, and respond to network detections across your environment." actions={<><LiveIndicator connected={liveConnected} /><Button variant="secondary" onClick={exportCsv}><Download size={15} /> Export CSV</Button>{user?.role === 'admin' && <Button onClick={simulateAlert}><Sparkles size={15} /> Simulate alert</Button>}</>} />
    <div className="alert-overview-strip"><div><span className="overview-icon overview-red"><AlertTriangle size={17} /></span><div><b>{alerts.filter((item) => item.severity === 'critical' && item.status !== 'resolved').length}</b><span>Critical requiring action</span></div></div><div><span className="overview-icon overview-amber"><ShieldAlert size={17} /></span><div><b>{alerts.filter((item) => item.status === 'new').length}</b><span>New detections</span></div></div><div><span className="overview-icon overview-cyan"><Activity size={17} /></span><div><b>{alerts.length}</b><span>All detections</span></div></div><div className="alert-stream-status"><i className="pulse-dot" /> Streaming live <span>·</span> updated moments ago</div></div>
    <section className="panel alert-page-panel">
      <div className="filter-toolbar">
        <div className="filter-left"><label className="filter-search"><Search size={15} /><input value={query} onChange={(event) => { setQuery(event.target.value); setPage(1) }} placeholder="Search IP, country, signature..." /></label><span className="filter-divider" /><div className="select-shell"><Filter size={14} /><select value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(1) }}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><ChevronDown size={13} /></div><div className="select-shell"><SlidersHorizontal size={14} /><select value={status} onChange={(event) => { setStatus(event.target.value); setPage(1) }}><option value="all">All statuses</option><option value="new">New</option><option value="investigating">Investigating</option><option value="blocked">Blocked</option><option value="resolved">Resolved</option></select><ChevronDown size={13} /></div></div>
        <div className="date-filters"><label>From <input type="date" value={dateFrom} onChange={(event) => { setDateFrom(event.target.value); setPage(1) }} /></label><label>To <input type="date" value={dateTo} onChange={(event) => { setDateTo(event.target.value); setPage(1) }} /></label><button className="clear-filters" onClick={() => { setDateFrom(''); setDateTo(''); setSeverity('all'); setStatus('all'); setQuery(''); setPage(1) }}><X size={13} /> Clear</button></div>
      </div>
      {selected.length > 0 && <div className="bulk-toolbar"><span><span className="bulk-count">{selected.length}</span> selected</span><div>{(user?.role === 'admin' || user?.role === 'analyst') && <Button variant="secondary" size="sm" onClick={bulkResolve}><Check size={14} /> Mark resolved</Button>}{user?.role === 'admin' && <Button variant="danger" size="sm" onClick={bulkBlock}><Ban size={14} /> Block IPs</Button>}<Button variant="ghost" size="sm" onClick={exportCsv}><Download size={14} /> Export selected</Button><IconButton label="Clear selection" onClick={() => setSelected([])}><X size={15} /></IconButton></div></div>}
      {rows.length === 0 ? <EmptyState icon={<AlertTriangle size={30} />} title="No detections found" description={alerts.length === 0 ? 'No alerts are available yet. New telemetry will appear here as sensors report activity.' : filtered.length === 0 ? 'No alerts match the current filters. Clear them to return to the full detection stream.' : 'There are no alerts on this page. Move back through the alert queue to see more results.'} action={<>{(query || severity !== 'all' || status !== 'all' || dateFrom || dateTo) && <Button variant="secondary" onClick={() => { setQuery(''); setSeverity('all'); setStatus('all'); setDateFrom(''); setDateTo(''); setSearchParams({}, { replace: true }); setPage(1) }}><X size={14} /> Clear filters</Button>}{user?.role === 'admin' && <Button onClick={simulateAlert}><Sparkles size={15} /> Simulate alert</Button>}</>} /> : <div className="table-wrap full-alert-table-wrap"><table className="data-table alert-table full-alert-table"><thead><tr><th className="checkbox-col"><input type="checkbox" checked={allPageSelected} onChange={togglePageSelect} aria-label="Select all on page" /></th><th><button className="sort-header" onClick={() => changeSort('timestamp')}>TIME <ChevronDown size={12} className={sortBy === 'timestamp' && !sortDesc ? 'sort-flipped' : ''} /></button></th><th><button className="sort-header" onClick={() => changeSort('severity')}>SEVERITY <ChevronDown size={12} className={sortBy === 'severity' && !sortDesc ? 'sort-flipped' : ''} /></button></th><th>SOURCE IP</th><th>COUNTRY</th><th>DESTINATION</th><th>ATTACK TYPE</th><th>STATUS</th><th className="align-right">ACTION</th></tr></thead><tbody>
        {rows.map((alert) => <tr key={alert.id} className="clickable-row" onClick={() => setDrawerAlert(alert)}><td className="checkbox-col" onClick={(event) => event.stopPropagation()}><input type="checkbox" checked={selected.includes(alert.id)} onChange={() => toggleSelect(alert.id)} aria-label={`Select ${alert.id}`} /></td><td><span className="table-time-stack"><b>{formatTime(alert.timestamp)}</b><small>{timeAgo(alert.timestamp)}</small></span></td><td><SeverityBadge severity={alert.severity} /></td><td><span className="mono-text ip-cell">{alert.sourceIp}</span></td><td>{alert.sourceCountry}</td><td><span className="mono-text table-destination">{alert.destinationIp}</span></td><td><span className="attack-type-cell">{alert.attackType}</span></td><td><StatusBadge status={alert.status} /></td><td className="align-right" onClick={(event) => event.stopPropagation()}><div className="alert-row-actions"><button className="table-quick-action" onClick={() => setDrawerAlert(alert)}>Inspect <ChevronRight size={13} /></button>{user?.role === 'admin' && <button className="table-quick-action table-block-action" onClick={() => void blockAlert(alert)} disabled={blockingAlertId !== null || isIPCurrentlyBlocked(blocks, alert.sourceIp)} title={isIPCurrentlyBlocked(blocks, alert.sourceIp) ? 'IP already blocked' : 'Block source IP'}><Ban size={12} />{blockingAlertId === alert.id ? 'Blocking…' : 'Block IP'}</button>}</div></td></tr>)}
      </tbody></table></div>}
      <div className="table-footer alerts-footer"><span>Showing <b>{filtered.length === 0 ? 0 : (page - 1) * pageSize + 1}–{Math.min(page * pageSize, filtered.length)}</b> of <b>{filtered.length}</b> alerts</span><div className="pagination"><span>Rows per page <b>25</b></span><button aria-label="Previous page" disabled={page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}><ChevronLeft size={15} /></button><strong>{page} <span>/</span> {pageCount}</strong><button aria-label="Next page" disabled={page >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}><ChevronRight size={15} /></button></div></div>
    </section>
    <AlertDrawer alert={drawerAlert} onClose={() => setDrawerAlert(null)} />
  </div>
}
