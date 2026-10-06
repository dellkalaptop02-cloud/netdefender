import { useState } from 'react'
import { toast } from 'sonner'
import { Activity, Database, HardDrive, MoreHorizontal, Radio, RefreshCw, RotateCw, Server, ShieldCheck, Signal } from 'lucide-react'
import { useAppStore } from '../store'
import { useLiveState } from '../lib/runtime'
import { formatTime } from '../lib/utils'
import type { Sensor } from '../types'
import { Button, EmptyState, LiveIndicator, PageHeader, StatusBadge } from '../components/Ui'

function Gauge({ value, label, tone }: { value: number; label: string; tone?: 'warning' | 'danger' }) {
  const color = tone === 'danger' ? '#ef4444' : tone === 'warning' || value > 75 ? '#f59e0b' : '#06b6d4'
  return <div className="sensor-gauge-row"><div className="sensor-gauge" style={{ background: `conic-gradient(${color} ${value * 3.6}deg, #202c3a 0deg)` }}><div><b>{value}%</b></div></div><div><span>{label}</span><small>{value > 80 ? 'High utilization' : value > 65 ? 'Elevated' : 'Normal range'}</small></div></div>
}

function SensorCard({ sensor, onRestart, canManage }: { sensor: Sensor; onRestart: (sensor: Sensor) => void; canManage: boolean }) {
  const typeIcon = sensor.type === 'Suricata' ? <ShieldCheck size={16} /> : sensor.type === 'Zeek' ? <Signal size={16} /> : <Server size={16} />
  return <article className={`sensor-card sensor-card-${sensor.status}`}>
    <div className="sensor-card-top"><div className={`sensor-type-icon sensor-type-${sensor.type.toLowerCase()}`}>{typeIcon}</div><button className="sensor-more" aria-label="Sensor options" title="Sensor details"><MoreHorizontal size={17} /></button></div>
    <div className="sensor-title-row"><div><h3>{sensor.name}</h3><span className="sensor-address"><span className="mono-text">{sensor.ip}</span><span className="sensor-address-dot">·</span>{sensor.type}</span></div><StatusBadge status={sensor.status} /></div>
    <div className="sensor-gauges"><Gauge value={sensor.cpu} label="CPU usage" tone={sensor.cpu > 85 ? 'danger' : sensor.cpu > 75 ? 'warning' : undefined} /><Gauge value={sensor.memory} label="Memory" tone={sensor.memory > 85 ? 'danger' : sensor.memory > 75 ? 'warning' : undefined} /></div>
    <div className="sensor-card-divider" />
    <div className="sensor-meta-row"><div><small>UPTIME</small><b>{sensor.uptime}</b></div><div><small>LAST HEARTBEAT</small><b>{sensor.status === 'offline' ? formatTime(sensor.lastHeartbeat, true) : 'Just now'}</b></div></div>
    <div className="sensor-card-footer"><span className={`sensor-status-line ${sensor.status}`}><i />{sensor.status === 'online' ? 'Healthy · ingesting traffic' : sensor.status === 'warning' ? 'Degraded · high utilization' : 'No heartbeat received'}</span><Button variant="secondary" size="sm" onClick={() => onRestart(sensor)} disabled={!canManage || sensor.status === 'warning'}><RotateCw size={13} /> Restart</Button></div>
  </article>
}

export default function SensorsPage() {
  const sensors = useAppStore((state) => state.sensors)
  const user = useAppStore((state) => state.user)
  const liveConnected = useLiveState((state) => state.connected)
  const updateSensor = useAppStore((state) => state.updateSensor)
  const [restarting, setRestarting] = useState<string | null>(null)
  const online = sensors.filter((sensor) => sensor.status === 'online').length
  const warnings = sensors.filter((sensor) => sensor.status === 'warning').length
  const offline = sensors.filter((sensor) => sensor.status === 'offline').length
  const restart = (sensor: Sensor) => {
    if (user?.role !== 'admin' || restarting) return
    setRestarting(sensor.id)
    updateSensor(sensor.id, { status: 'warning', cpu: 5 })
    toast.info(`Restarting ${sensor.name}`, { description: 'Sensor will reconnect in a few seconds.' })
    window.setTimeout(() => {
      updateSensor(sensor.id, { status: 'online', cpu: 26 + Math.floor(Math.random() * 24), memory: 49 + Math.floor(Math.random() * 18), uptime: '00d 00h 01m', lastHeartbeat: new Date().toISOString() })
      setRestarting(null); toast.success(`${sensor.name} is back online`)
    }, 2300)
  }

  return <div className="page">
    <PageHeader eyebrow="INFRASTRUCTURE HEALTH" title="Network sensors" description="Monitor the health and coverage of your distributed detection fleet." actions={<><LiveIndicator connected={liveConnected} /><Button variant="secondary" onClick={() => toast.success('Sensor heartbeat check complete', { description: `${online} online · ${warnings} warning · ${offline} offline` })}><RefreshCw size={15} /> Refresh status</Button>{user?.role === 'admin' && <Button onClick={() => toast.info('Sensor enrollment', { description: 'Use the onboarding guide in Documentation to connect a new sensor.' })}><Radio size={15} /> Connect sensor</Button>}</>} />
    <div className="sensor-health-banner"><div className="sensor-health-icon"><Activity size={19} /></div><div className="sensor-health-summary"><b>Sensor network <span>operational</span></b><p>Detection coverage is active across <strong>{online} of {sensors.length}</strong> nodes. Last fleet heartbeat received just now.</p></div><div className="sensor-health-counts"><div className="sensor-health-count"><i className="status-dot online-dot" /><b>{online}</b><span>Online</span></div><div className="sensor-health-count"><i className="status-dot warning-dot" /><b>{warnings}</b><span>Warning</span></div><div className="sensor-health-count"><i className="status-dot offline-dot" /><b>{offline}</b><span>Offline</span></div></div><span className="sensor-health-bg" /></div>
    <div className="sensor-section-heading"><div><h2>Sensor fleet <span>{sensors.length}</span></h2><p>Suricata, Zeek, and Wazuh agents in your environment</p></div><div className="sensor-legend"><span><i className="status-dot online-dot" /> Normal</span><span><i className="status-dot warning-dot" /> Warning</span><span><i className="status-dot offline-dot" /> Offline</span></div></div>
    <div className="sensor-grid">{sensors.length === 0 ? <EmptyState icon={<Radio size={30} />} title="No sensors connected" description="Enroll a sensor to start ingesting network telemetry and monitor fleet health from this workspace." action={user?.role === 'admin' ? <Button onClick={() => toast.info('Sensor enrollment', { description: 'Use the onboarding guide in Documentation to connect a new sensor.' })}><Radio size={15} /> Connect sensor</Button> : undefined} /> : sensors.map((sensor) => <SensorCard key={sensor.id} sensor={sensor} onRestart={restart} canManage={user?.role === 'admin'} />)}</div>
    <div className="sensor-footnote"><Database size={14} /><span>Sensor metrics update every 15 seconds.</span><span className="sensor-footnote-right"><HardDrive size={14} /> Fleet management service healthy</span></div>
  </div>
}
