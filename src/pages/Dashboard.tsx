import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import { CircleMarker, MapContainer, Popup, TileLayer } from 'react-leaflet'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts'
import { Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, ArrowUpRightFromSquare, Ban, ChevronRight, Clock3, Crosshair, Download, Radio, ShieldAlert, TrendingUp, Zap } from 'lucide-react'
import { useAppStore } from '../store'
import { useLiveState } from '../lib/runtime'
import { createIPBlock, isIPCurrentlyBlocked } from '../lib/responseActions'
import { formatTime, timeAgo } from '../lib/utils'
import type { Alert } from '../types'
import { Button, LiveIndicator, PageHeader, SectionTitle, SeverityBadge, StatusBadge } from '../components/Ui'
import AlertDrawer from '../components/AlertDrawer'

const chartColors = ['#06b6d4', '#10b981', '#f59e0b', '#f97316', '#a78bfa', '#ef4444', '#38bdf8', '#e879f9']

function buildHourlyData(alerts: Alert[]) {
  const now = Date.now()
  return Array.from({ length: 24 }, (_, index) => {
    const hourAgo = 23 - index
    const start = now - (hourAgo + 1) * 3600_000
    const end = now - hourAgo * 3600_000
    const count = alerts.filter((alert) => {
      const time = new Date(alert.timestamp).getTime()
      return time >= start && time < end
    }).length
    const time = new Date(end)
    return { time: time.toLocaleTimeString('en-US', { hour: '2-digit', hour12: false }), alerts: count, critical: alerts.filter((alert) => { const t = new Date(alert.timestamp).getTime(); return t >= start && t < end && alert.severity === 'critical' }).length }
  })
}

function DashboardTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ value: number; dataKey?: string }>; label?: string }) {
  if (!active || !payload?.length) return null
  return <div className="chart-tooltip"><strong>{label}</strong>{payload.map((item, index) => <div key={index}><i style={{ background: item.dataKey === 'critical' ? '#ef4444' : '#06b6d4' }} />{item.dataKey === 'critical' ? 'Critical' : 'Alerts'} <b>{item.value}</b></div>)}</div>
}

function AttackTooltip({ active, payload }: { active?: boolean; payload?: Array<{ name: string; value: number; color?: string }> }) {
  if (!active || !payload?.length) return null
  return <div className="chart-tooltip"><strong>{payload[0].name}</strong><div><i style={{ background: payload[0].color }} />Detections <b>{payload[0].value}</b></div></div>
}

function MetricCard({ label, value, delta, icon: Icon, tint, foot, trend = 'up' }: { label: string; value: string | number; delta: string; icon: typeof ShieldAlert; tint: string; foot: string; trend?: 'up' | 'down' }) {
  return <div className={`metric-card metric-${tint}`}>
    <div className="metric-head"><span>{label}</span><span className="metric-icon"><Icon size={18} strokeWidth={1.8} /></span></div>
    <div className="metric-number-row"><strong>{value}</strong><span className={`metric-delta ${trend === 'down' ? 'delta-good' : ''}`}>{trend === 'up' ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />}{delta}</span></div>
    <div className="metric-foot"><span>{foot}</span><span className="metric-sparkline"><i /><i /><i /><i /><i /><i /><i /><i /><i /></span></div>
    <div className="metric-glow" />
  </div>
}

function WorldThreatMap({ alerts }: { alerts: Alert[] }) {
  const points = useMemo(() => alerts.filter((alert): alert is Alert & { sourceLat: number; sourceLng: number } =>
    typeof alert.sourceLat === 'number' && Number.isFinite(alert.sourceLat) && alert.sourceLat >= -90 && alert.sourceLat <= 90 &&
    typeof alert.sourceLng === 'number' && Number.isFinite(alert.sourceLng) && alert.sourceLng >= -180 && alert.sourceLng <= 180,
  ), [alerts])
  return <div className="map-wrap">
    <MapContainer center={[25, 7]} zoom={1.55} minZoom={1.4} maxZoom={5} scrollWheelZoom={false} zoomControl={false} worldCopyJump className="threat-map">
      <TileLayer attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>' url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png" />
      {points.map((alert) => <CircleMarker key={alert.id} center={[alert.sourceLat, alert.sourceLng]} radius={alert.severity === 'critical' ? 6.5 : alert.severity === 'high' ? 5.5 : 4.5} pathOptions={{ color: '#ff777d', weight: 2, fillColor: '#ef4444', fillOpacity: 0.78, className: 'map-pulse-marker' }}>
        <Popup className="threat-popup" closeButton>
          <div className="threat-popup-content">
            <div className="threat-popup-badges"><SeverityBadge severity={alert.severity} /><StatusBadge status={alert.status} /></div>
            <h3>{alert.attackType}</h3>
            <div className="threat-popup-details"><span>Source</span><code>{alert.sourceIp}</code><span>Origin</span><b>{alert.sourceCountry}</b><span>Coordinates</span><code>{alert.sourceLat.toFixed(3)}, {alert.sourceLng.toFixed(3)}</code><span>Destination</span><code>{alert.destinationIp}</code><span>Protocol</span><b>{alert.protocol}</b><span>Detected</span><b>{formatTime(alert.timestamp, true)}</b></div>
            <p>{alert.signature}</p>
          </div>
        </Popup>
      </CircleMarker>)}
    </MapContainer>
    <div className="map-overlay-top"><span><span className="map-live-dot" /> ATTACK ORIGINS</span><span>LIVE GEOINT</span></div>
    <div className="map-legend"><span><i className="legend-critical" /> Alert sources</span><span>{points.length} mapped</span></div>
    <div className="map-scale">GEOIP · {points.length} ALERTS</div>
  </div>
}

export default function DashboardPage() {
  const alerts = useAppStore((state) => state.alerts)
  const user = useAppStore((state) => state.user)
  const blocks = useAppStore((state) => state.blockedIPs)
  const sensors = useAppStore((state) => state.sensors)
  const liveConnected = useLiveState((state) => state.connected)
  const liveAlertId = useLiveState((state) => state.liveAlertId)
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [blockingAlertId, setBlockingAlertId] = useState<string | null>(null)
  const [range, setRange] = useState<'24H' | '7D'>('24H')

  const metrics = useQuery({ queryKey: ['soc-metrics', alerts.length, blocks.length, sensors.length], queryFn: async () => {
    const since = Date.now() - 24 * 3600_000
    const lastDay = alerts.filter((alert) => new Date(alert.timestamp).getTime() >= since)
    return { today: lastDay.length, critical: lastDay.filter((alert) => alert.severity === 'critical').length, blocked: blocks.filter((item) => item.isActive).length, online: sensors.filter((item) => item.status === 'online').length, total: sensors.length }
  }, refetchInterval: 30_000 })
  const stats = metrics.data || { today: alerts.length, critical: alerts.filter((alert) => alert.severity === 'critical').length, blocked: blocks.filter((item) => item.isActive).length, online: sensors.filter((item) => item.status === 'online').length, total: sensors.length }

  const hourlyData = useMemo(() => buildHourlyData(alerts), [alerts])
  const trendData = range === '24H' ? hourlyData : hourlyData.map((item, index) => ({ ...item, time: `${index + 1}d`, alerts: item.alerts + (index % 4 === 0 ? 4 : 0) }))
  const attackData = useMemo(() => {
    const values = new Map<string, number>()
    alerts.forEach((item) => values.set(item.attackType, (values.get(item.attackType) || 0) + 1))
    return [...values.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([name, value], index) => ({ name, value, color: chartColors[index] }))
  }, [alerts])
  const countryData = useMemo(() => {
    const values = new Map<string, number>()
    alerts.forEach((item) => values.set(item.sourceCountry, (values.get(item.sourceCountry) || 0) + 1))
    return [...values.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([country, count], index) => ({ country: country === 'United States' ? 'USA' : country === 'North Korea' ? 'N. Korea' : country, count, color: index === 0 ? '#06b6d4' : '#164e63' }))
  }, [alerts])
  // Alert arrivals are prepended by the store, so a newly received event always enters at the top of the feed.
  const liveAlerts = useMemo(() => alerts.slice(0, 20), [alerts])
  const blockAlert = async (alert: Alert) => {
    if (user?.role !== 'admin' || blockingAlertId) return
    if (isIPCurrentlyBlocked(blocks, alert.sourceIp)) { toast.info('IP is already on the block list'); return }
    setBlockingAlertId(alert.id)
    try {
      const result = await createIPBlock({ ip: alert.sourceIp, reason: `${alert.attackType} · alert ${alert.id}`, expiresAt: null, user, sourceAlert: alert })
      if (result.alreadyBlocked) { toast.info('IP is already on the block list'); return }
      toast.success(`${alert.sourceIp} blocked`, { description: 'The alert was marked blocked and recorded in the audit log.' })
    } catch (error) {
      toast.error('Could not block source IP', { description: error instanceof Error ? error.message : 'Try again or contact your administrator.' })
    } finally { setBlockingAlertId(null) }
  }

  return <div className="page page-dashboard">
    <PageHeader eyebrow="SECURITY OPERATIONS CENTER" title={`Good morning, ${user?.fullName?.split(' ')[0] || 'operator'}`} description="Your network is being watched. Here's what's happening across your environment." actions={<div className="dashboard-header-actions"><div className={`live-chip ${liveConnected ? '' : 'live-chip-offline'}`}><span className={liveConnected ? 'pulse-dot' : 'status-dot warning-dot'} /> {liveConnected ? 'LIVE' : 'RECONNECTING'} <span className="live-separator" /> {liveConnected ? 'STREAM CONNECTED' : 'WAITING FOR STREAM'}</div><Button variant="secondary" onClick={() => window.print()}><Download size={15} /> Export overview</Button></div>} />

    <div className="dashboard-stat-grid">
      <MetricCard label="Total alerts today" value={stats.today.toLocaleString()} delta="12.8%" icon={ShieldAlert} tint="cyan" foot="vs. previous 24 hours" />
      <MetricCard label="Critical alerts" value={stats.critical.toString().padStart(2, '0')} delta="3 new" icon={AlertTriangle} tint="red" foot="requires immediate attention" />
      <MetricCard label="Blocked IPs" value={stats.blocked.toString().padStart(2, '0')} delta="8.2%" icon={Ban} tint="amber" foot="active deny-list entries" trend="down" />
      <MetricCard label="Active sensors" value={`${stats.online}/${stats.total}`} delta="All healthy" icon={Radio} tint="green" foot="3 online · 1 warning · 1 offline" trend="down" />
    </div>

    <div className="dashboard-chart-grid">
      <section className="panel chart-panel trend-panel">
        <SectionTitle title="Alerts — Last 24 Hours" subtitle="Detection volume across all sensors" icon={<Activity size={16} />} action={<div className="chart-controls"><div className="chart-legend"><i /> Alerts <i className="legend-red" /> Critical</div><div className="segmented-control"><button className={range === '24H' ? 'selected' : ''} onClick={() => setRange('24H')}>24h</button><button className={range === '7D' ? 'selected' : ''} onClick={() => setRange('7D')}>7d</button></div></div>} />
        <div className="chart-large"><ResponsiveContainer width="100%" height="100%"><AreaChart data={trendData} margin={{ top: 14, right: 6, left: -20, bottom: 0 }}>
          <defs><linearGradient id="cyanFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#06b6d4" stopOpacity={0.32} /><stop offset="95%" stopColor="#06b6d4" stopOpacity={0} /></linearGradient></defs>
          <CartesianGrid stroke="#1c2937" strokeDasharray="3 5" vertical={false} />
          <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#617386', fontSize: 10 }} interval={3} />
          <YAxis axisLine={false} tickLine={false} tick={{ fill: '#617386', fontSize: 10 }} />
          <ChartTooltip content={<DashboardTooltip />} cursor={{ stroke: '#305064', strokeDasharray: '4 4' }} />
          <Area type="monotone" dataKey="alerts" stroke="#06b6d4" strokeWidth={2.2} fill="url(#cyanFill)" activeDot={{ r: 4, fill: '#e5fdff', stroke: '#06b6d4', strokeWidth: 2 }} />
          <Area type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={1.5} fill="transparent" activeDot={{ r: 3, fill: '#ef4444', stroke: '#fecaca' }} />
        </AreaChart></ResponsiveContainer></div>
        <div className="chart-bottom-summary"><div><span>Peak activity</span><strong>09:00 — 10:00 UTC</strong></div><div><span>Alerts per hour</span><strong>{(alerts.length / 24).toFixed(1)} <small>avg</small></strong></div><div className="trend-note"><TrendingUp size={14} /> Threat volume elevated</div></div>
      </section>

      <section className="panel chart-panel attack-panel">
        <SectionTitle title="Attack types" subtitle="Classification by signature" icon={<Crosshair size={16} />} action={<button className="text-action" onClick={() => window.location.assign('/alerts')}>Details <ChevronRight size={14} /></button>} />
        <div className="donut-wrap"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={attackData} dataKey="value" nameKey="name" cx="50%" cy="47%" innerRadius="60%" outerRadius="82%" paddingAngle={4} stroke="none">{attackData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}</Pie><ChartTooltip content={<AttackTooltip />} /></PieChart></ResponsiveContainer><div className="donut-center"><strong>{alerts.length}</strong><span>DETECTIONS</span></div></div>
        <div className="attack-legend">{attackData.slice(0, 4).map((entry) => <div key={entry.name}><span><i style={{ backgroundColor: entry.color }} />{entry.name}</span><b>{entry.value}</b></div>)}</div>
      </section>
    </div>

    <div className="dashboard-lower-grid">
      <section className="panel country-panel">
        <SectionTitle title="Top source countries" subtitle="Origin of detections by GeoIP" icon={<ArrowUpRight size={16} />} action={<button className="icon-subtle" onClick={() => window.location.assign('/reports')} aria-label="Open reports"><ArrowUpRightFromSquare size={15} /></button>} />
        <div className="country-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={countryData} layout="vertical" margin={{ top: 4, right: 25, left: 3, bottom: 0 }} barCategoryGap={10}>
          <CartesianGrid stroke="#1c2937" strokeDasharray="3 4" horizontal={false} />
          <XAxis type="number" axisLine={false} tickLine={false} tick={{ fill: '#617386', fontSize: 10 }} />
          <YAxis type="category" dataKey="country" axisLine={false} tickLine={false} tick={{ fill: '#9fb2c4', fontSize: 11 }} width={78} />
          <ChartTooltip cursor={{ fill: 'rgba(6,182,212,.06)' }} contentStyle={{ background: '#111827', border: '1px solid #243247', borderRadius: 8, fontSize: 11 }} />
          <Bar dataKey="count" radius={[0, 5, 5, 0]} barSize={10}>{countryData.map((entry) => <Cell key={entry.country} fill={entry.color} />)}</Bar>
        </BarChart></ResponsiveContainer></div>
      </section>
      <section className="panel map-panel"><SectionTitle title="Global threat map" subtitle="Live source locations of active threats" icon={<Crosshair size={16} />} action={<span className="map-region-label"><span className="pulse-dot" /> GLOBAL VIEW</span>} /><WorldThreatMap alerts={alerts} /></section>
    </div>

    <section className="panel live-feed-panel">
      <SectionTitle title="Live alert feed" subtitle={<>{liveAlerts.length} latest detections <span className="section-subtle-separator">·</span> auto-refreshing in real time</>} icon={<Zap size={16} />} action={<div className="feed-actions"><LiveIndicator connected={liveConnected} /><Button variant="secondary" size="sm" onClick={() => window.location.assign('/alerts')}>View all alerts <ChevronRight size={14} /></Button></div>} />
      <div className="table-wrap dashboard-table-wrap"><table className="data-table alert-table"><thead><tr><th>DETECTED</th><th>SEVERITY</th><th>SOURCE IP</th><th>COUNTRY</th><th>ATTACK TYPE</th><th>STATUS</th><th className="align-right">ACTIONS</th></tr></thead><tbody>
        {liveAlerts.map((alert) => <tr key={alert.id} onClick={() => setSelectedAlert(alert)} className={`clickable-row ${alert.id === liveAlertId ? 'alert-feed-row-enter' : ''}`}><td><span className="time-cell"><Clock3 size={12} />{timeAgo(alert.timestamp)}</span></td><td><SeverityBadge severity={alert.severity} /></td><td><span className="mono-text ip-cell">{alert.sourceIp}</span></td><td><span className="country-cell"><span className="country-dot" />{alert.sourceCountry}</span></td><td><span className="attack-type-cell">{alert.attackType}</span></td><td><StatusBadge status={alert.status} /></td><td className="align-right" onClick={(event) => event.stopPropagation()}><div className="row-action-buttons"><button className="row-investigate" onClick={() => setSelectedAlert(alert)}>Investigate <ArrowUpRight size={12} /></button><button className="row-block" onClick={() => blockAlert(alert)} disabled={user?.role !== 'admin' || blockingAlertId !== null || isIPCurrentlyBlocked(blocks, alert.sourceIp)} title={user?.role !== 'admin' ? 'Administrator access required' : blockingAlertId === alert.id ? 'Blocking…' : isIPCurrentlyBlocked(blocks, alert.sourceIp) ? 'IP already blocked' : 'Block source IP'} aria-label={`Block source IP ${alert.sourceIp}`}><Ban size={13} /></button></div></td></tr>)}
      </tbody></table></div>
      <div className="table-footer"><span><span className="table-live-dot" /> Showing <b>20</b> of {alerts.length} detections</span><button onClick={() => window.location.assign('/alerts')}>Open alert queue <ChevronRight size={13} /></button></div>
    </section>
    <AlertDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
  </div>
}
