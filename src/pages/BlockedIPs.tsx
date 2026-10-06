import { useMemo, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { Ban, ChevronDown, CircleCheck, Clock3, Download, Globe2, Plus, Search, ShieldAlert, ShieldCheck, Unplug, X } from 'lucide-react'
import { useAppStore } from '../store'
import { useLiveState } from '../lib/runtime'
import { createIPBlock, releaseIPBlock } from '../lib/responseActions'
import { downloadText, formatTime } from '../lib/utils'
import type { BlockedIP } from '../types'
import { Button, EmptyState, LiveIndicator, Modal, PageHeader, StatusBadge } from '../components/Ui'

const ipPattern = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/
const blockSchema = z.object({ ip: z.string().regex(ipPattern, 'Enter a valid IPv4 address'), reason: z.string().min(3, 'Add a reason (at least 3 characters)').max(160), duration: z.enum(['permanent', '1h', '24h', '7d']) })
type BlockForm = z.infer<typeof blockSchema>

export default function BlockedIPsPage() {
  const blockedIPs = useAppStore((state) => state.blockedIPs)
  const user = useAppStore((state) => state.user)
  const liveConnected = useLiveState((state) => state.connected)
  const [filter, setFilter] = useState<'active' | 'expired' | 'all'>('active')
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [pendingUnblockId, setPendingUnblockId] = useState<string | null>(null)
  const { register, handleSubmit, reset, formState: { errors, isSubmitting } } = useForm<BlockForm>({ resolver: zodResolver(blockSchema), defaultValues: { duration: '24h' } })

  const visible = useMemo(() => blockedIPs.filter((entry) => {
    const state = entry.isActive && (!entry.expiresAt || new Date(entry.expiresAt) > new Date()) ? 'active' : 'expired'
    return (filter === 'all' || state === filter) && (!query || `${entry.ip} ${entry.reason} ${entry.blockedBy}`.toLowerCase().includes(query.toLowerCase()))
  }).sort((a, b) => new Date(b.blockedAt).getTime() - new Date(a.blockedAt).getTime()), [blockedIPs, filter, query])

  const submit = handleSubmit(async (values) => {
    const expiry = values.duration === 'permanent' ? null : new Date(Date.now() + ({ '1h': 3600_000, '24h': 86400_000, '7d': 604800_000 }[values.duration])).toISOString()
    try {
      const result = await createIPBlock({ ip: values.ip, reason: values.reason, expiresAt: expiry, user })
      if (result.alreadyBlocked) { toast.error('This IP address is already blocked'); return }
      toast.success(`${values.ip} added to block list`); setOpen(false); reset({ ip: '', reason: '', duration: '24h' })
    } catch (error) {
      toast.error('Could not add IP to block list', { description: error instanceof Error ? error.message : 'Try again or contact your administrator.' })
    }
  })

  const handleUnblock = async (entry: BlockedIP) => {
    if (pendingUnblockId) return
    setPendingUnblockId(entry.id)
    try {
      const result = await releaseIPBlock(entry, user)
      if (result.alreadyUnblocked) { toast.info(`${entry.ip} is already unblocked`); return }
      toast.success(`${entry.ip} removed from active block list`)
    } catch (error) {
      toast.error('Could not unblock IP', { description: error instanceof Error ? error.message : 'Try again or contact your administrator.' })
    } finally { setPendingUnblockId(null) }
  }
  const exportJson = () => { downloadText('netdefender-blocked-ips.json', JSON.stringify(blockedIPs, null, 2)); toast.success('Block list exported') }
  const activeCount = blockedIPs.filter((item) => item.isActive && (!item.expiresAt || new Date(item.expiresAt) > new Date())).length

  return <div className="page">
    <PageHeader eyebrow="NETWORK CONTROLS" title="Blocked IP addresses" description="Manage source addresses that are denied at your network perimeter." actions={<><Button variant="secondary" onClick={exportJson}><Download size={15} /> Export list</Button>{user?.role === 'admin' && <Button onClick={() => setOpen(true)}><Plus size={16} /> Block new IP</Button>}</>} />
    <div className="blocked-summary-row"><div className="blocked-summary-card"><span className="blocked-summary-icon"><Ban size={18} /></span><div><small>ACTIVE BLOCKS</small><b>{activeCount.toString().padStart(2, '0')}</b><span>Enforced across all sensors</span></div></div><div className="blocked-summary-card"><span className="blocked-summary-icon blocked-icon-green"><ShieldCheck size={18} /></span><div><small>THREATS STOPPED</small><b>1,284</b><span>In the last 30 days</span></div></div><div className="blocked-summary-card"><span className="blocked-summary-icon blocked-icon-amber"><Clock3 size={18} /></span><div><small>EXPIRING SOON</small><b>{blockedIPs.filter((item) => item.isActive && item.expiresAt && (new Date(item.expiresAt).getTime() - Date.now()) < 86400_000 && new Date(item.expiresAt).getTime() > Date.now()).length.toString().padStart(2, '0')}</b><span>Within the next 24 hours</span></div></div></div>
    <section className="panel blocked-table-panel"><div className="blocked-table-toolbar"><div className="segmented-control filter-tabs"><button className={filter === 'active' ? 'selected' : ''} onClick={() => setFilter('active')}>Active <span>{activeCount}</span></button><button className={filter === 'expired' ? 'selected' : ''} onClick={() => setFilter('expired')}>Expired</button><button className={filter === 'all' ? 'selected' : ''} onClick={() => setFilter('all')}>All entries <span>{blockedIPs.length}</span></button></div><label className="filter-search blocked-search"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter IP or reason" /></label><LiveIndicator connected={liveConnected} /></div>
      {visible.length === 0 ? <EmptyState icon={<Ban size={30} />} title={blockedIPs.length > 0 ? 'No entries match these filters' : 'No blocked IPs yet'} description={blockedIPs.length > 0 ? 'Try another status or clear the address search to view your block list.' : 'Block a suspicious source address or let an automation playbook contain a threat.'} action={<>{(filter !== 'all' || query) && <Button variant="secondary" onClick={() => { setFilter('all'); setQuery('') }}><X size={14} /> Clear filters</Button>}{user?.role === 'admin' && <Button onClick={() => setOpen(true)}><Plus size={15} /> Block an IP</Button>}</>} /> : <div className="table-wrap"><table className="data-table blocked-table"><thead><tr><th>IP ADDRESS</th><th>REASON</th><th>BLOCKED BY</th><th>BLOCKED AT</th><th>EXPIRES</th><th>STATUS</th><th className="align-right">ACTION</th></tr></thead><tbody>{visible.map((entry) => {
        const expired = !entry.isActive || (!!entry.expiresAt && new Date(entry.expiresAt) <= new Date())
        return <tr key={entry.id}><td><span className="blocked-ip-cell"><span className="blocked-ip-icon"><Globe2 size={14} /></span><b className="mono-text">{entry.ip}</b></span></td><td><span className="reason-cell">{entry.reason}</span></td><td><span className="blocked-by-cell"><span className="blocked-by-avatar">{entry.blockedBy.split(' ').map((p) => p[0]).join('')}</span>{entry.blockedBy}</span></td><td><span className="table-time-stack"><b>{formatTime(entry.blockedAt, true)}</b><small>Security event</small></span></td><td><span className="expires-cell">{entry.expiresAt ? formatTime(entry.expiresAt, true) : 'Never'}</span></td><td><StatusBadge status={expired ? 'expired' : 'active'} /></td><td className="align-right">{!expired && user?.role === 'admin' ? <button className="unblock-button" onClick={() => void handleUnblock(entry)} disabled={pendingUnblockId !== null} aria-busy={pendingUnblockId === entry.id}><Unplug size={13} />{pendingUnblockId === entry.id ? 'Unblocking…' : 'Unblock'}</button> : <span className="muted-dash">—</span>}</td></tr>
      })}</tbody></table></div>}
      <div className="table-footer"><span>Showing <b>{visible.length}</b> of {blockedIPs.length} addresses <span className="section-subtle-separator">·</span> auto-expire enabled</span><span className="secure-status"><CircleCheck size={14} /> Firewall sync healthy</span></div>
    </section>
    <Modal open={open} onClose={() => { setOpen(false); reset() }} title="Block an IP address" subtitle="Add a source address to your active deny list." size="md" footer={<><Button variant="ghost" onClick={() => { setOpen(false); reset() }}>Cancel</Button><Button variant="danger" onClick={submit} disabled={isSubmitting}><Ban size={15} /> Block address</Button></>}>
      <form className="form-stack" onSubmit={submit}>
        <label className="form-field"><span>IP address <b>*</b></span><div className="input-with-icon"><Globe2 size={15} /><input placeholder="203.0.113.42" className="mono-text" {...register('ip')} /></div>{errors.ip && <small className="field-error">{errors.ip.message}</small>}<small className="field-help">IPv4 address to deny at the network perimeter.</small></label>
        <label className="form-field"><span>Reason for blocking <b>*</b></span><input placeholder="e.g. Repeated SSH brute force" {...register('reason')} />{errors.reason && <small className="field-error">{errors.reason.message}</small>}</label>
        <label className="form-field"><span>Block duration</span><div className="select-input"><select {...register('duration')}><option value="1h">1 hour</option><option value="24h">24 hours</option><option value="7d">7 days</option><option value="permanent">Permanent</option></select><ChevronDown size={14} /></div>{errors.duration && <small className="field-error">{errors.duration.message}</small>}</label>
        <div className="form-security-note"><ShieldAlert size={16} /><span>This change will be recorded in your audit trail and synced to all active firewall sensors.</span></div>
      </form>
    </Modal>
  </div>
}
