import { useState } from 'react'
import { toast } from 'sonner'
import { ArrowDownRight, ArrowUpRight, Ban, Check, Clock3, Copy, ExternalLink, Globe2, Network, ShieldAlert, X } from 'lucide-react'
import { useAppStore } from '../store'
import type { Alert } from '../types'
import { formatTime, timeAgo } from '../lib/utils'
import { createIPBlock, isIPCurrentlyBlocked } from '../lib/responseActions'
import { Avatar, Button, IconButton, SeverityBadge, StatusBadge } from './Ui'

export default function AlertDrawer({ alert, onClose }: { alert: Alert | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  const [blocking, setBlocking] = useState(false)
  const user = useAppStore((state) => state.user)
  const blockedIPs = useAppStore((state) => state.blockedIPs)
  const updateAlert = useAppStore((state) => state.updateAlert)
  if (!alert) return null
  const alreadyBlocked = isIPCurrentlyBlocked(blockedIPs, alert.sourceIp)

  const blockIp = async () => {
    if (blocking || alreadyBlocked) { if (alreadyBlocked) toast.info('IP is already on the block list'); return }
    setBlocking(true)
    try {
      const result = await createIPBlock({ ip: alert.sourceIp, reason: `${alert.attackType} · alert ${alert.id}`, expiresAt: null, user, sourceAlert: alert })
      if (result.alreadyBlocked) { toast.info('IP is already on the block list'); return }
      toast.success(`${alert.sourceIp} blocked`, { description: 'The alert was marked blocked and the action was recorded in the audit log.' })
      onClose()
    } catch (error) {
      toast.error('Could not block source IP', { description: error instanceof Error ? error.message : 'Try again or contact your administrator.' })
    } finally { setBlocking(false) }
  }

  const copyIp = async () => {
    try { await navigator.clipboard.writeText(alert.sourceIp); setCopied(true); toast.success('Source IP copied'); setTimeout(() => setCopied(false), 1600) } catch { toast.error('Clipboard access unavailable') }
  }

  const resolve = () => { updateAlert(alert.id, { status: 'resolved' }); toast.success('Alert marked resolved'); onClose() }

  return <div className="drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <aside className="alert-drawer" role="dialog" aria-modal="true" aria-label="Alert investigation details">
      <div className="drawer-header"><div><div className="drawer-kicker"><span className="drawer-signal"><ShieldAlert size={14} /></span> DETECTION DETAILS</div><h2>{alert.attackType}</h2><div className="drawer-subline"><span className="mono-text">{alert.id}</span><span>·</span><span>{timeAgo(alert.timestamp)}</span></div></div><IconButton label="Close alert details" onClick={onClose}><X size={18} /></IconButton></div>
      <div className="drawer-scroll">
        <div className="drawer-badges"><SeverityBadge severity={alert.severity} /><StatusBadge status={alert.status} /><span className="drawer-detected">Detected {formatTime(alert.timestamp, true)}</span></div>
        <div className="drawer-actions">{user?.role === 'admin' && <Button variant="danger" onClick={blockIp} disabled={blocking || alreadyBlocked}><Ban size={15} />{blocking ? ' Blocking…' : alreadyBlocked ? ' Already blocked' : ' Block source IP'}</Button>}{(user?.role === 'admin' || user?.role === 'analyst') && <Button variant="secondary" onClick={resolve}><Check size={15} /> Resolve alert</Button>}{user?.role === 'viewer' && <span className="viewer-readonly-note">Read-only access</span>}</div>
        <section className="detail-section"><h3>Traffic path</h3><div className="traffic-path"><div className="traffic-endpoint"><span className="endpoint-icon endpoint-source"><ArrowUpRight size={15} /></span><div><small>SOURCE · {alert.sourceCountry.toUpperCase()}</small><b className="mono-text">{alert.sourceIp}</b><span className="endpoint-country"><Globe2 size={12} /> {alert.sourceCountry}</span></div><button onClick={copyIp} className="copy-mini" title="Copy source IP">{copied ? <Check size={14} /> : <Copy size={14} />}</button></div><div className="traffic-connector"><span /><small>{alert.protocol}</small><span /></div><div className="traffic-endpoint"><span className="endpoint-icon endpoint-target"><ArrowDownRight size={15} /></span><div><small>DESTINATION · INTERNAL</small><b className="mono-text">{alert.destinationIp}</b><span className="endpoint-country"><Network size={12} /> Application subnet</span></div></div></div></section>
        <section className="detail-section"><h3>Detection context</h3><div className="detail-grid"><div><small>Signature</small><strong>{alert.signature}</strong></div><div><small>Protocol</small><strong>{alert.protocol} · Layer 4</strong></div><div><small>Attack classification</small><strong>{alert.attackType}</strong></div><div><small>Sensor source</small><strong>Edge-Sensor-01 <span className="sensor-status-inline" /></strong></div></div></section>
        <section className="detail-section"><div className="section-title"><h3>Raw event log</h3><span className="terminal-label"><i /> LIVE EVENT</span></div><pre className="raw-log">{alert.rawLog}</pre></section>
        <section className="detail-section"><h3>Response timeline</h3><div className="timeline"><div className="timeline-row"><i className="timeline-point critical-point" /><div><b>Threat signature matched</b><p>Sensor detected a behavioral pattern consistent with {alert.attackType.toLowerCase()}.</p><time><Clock3 size={12} /> {formatTime(alert.timestamp, true)}</time></div></div><div className="timeline-row"><i className="timeline-point" /><div><b>Alert routed to SOC</b><p>Enriched with GeoIP, asset context, and threat intelligence.</p><time><Clock3 size={12} /> {formatTime(alert.timestamp, true)}</time></div></div></div></section>
        <section className="drawer-assignee"><Avatar name="Maya Chen" size="sm" /><div><small>Assigned analyst</small><b>Maya Chen</b></div>{(user?.role === 'admin' || user?.role === 'analyst') && <Button variant="ghost" size="sm" onClick={() => { updateAlert(alert.id, { status: 'investigating' }); toast.success('Alert assigned for investigation') }}>Assign to me</Button>}</section>
      </div>
      <div className="drawer-footer"><button onClick={() => { navigator.clipboard?.writeText(alert.id); toast.success('Alert ID copied') }}><Copy size={14} /> Copy alert ID</button><button onClick={() => { toast.info('Incident creation', { description: 'This alert is ready to be attached to a new incident.' }) }}><ExternalLink size={14} /> Create incident</button></div>
    </aside>
  </div>
}
