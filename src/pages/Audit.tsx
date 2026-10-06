import { useMemo, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { Activity, ArrowUpRight, ChevronDown, Download, Fingerprint, Search, Shield, UserRound, X } from 'lucide-react'
import { useAppStore } from '../store'
import { downloadText, formatTime, timeAgo } from '../lib/utils'
import { Button, EmptyState, PageHeader } from '../components/Ui'

const actionLabels: Record<string, string> = {
  'blocked_ip.added': 'IP blocked', 'blocked_ip.removed': 'IP unblocked', 'incident.updated': 'Incident updated', 'incident.created': 'Incident created',
  'alert.resolved': 'Alert resolved', 'firewall_rule.toggled': 'Firewall rule changed', 'firewall_rule.created': 'Firewall rule created',
  'firewall_rule.updated': 'Firewall rule updated', 'firewall.kill_switch': 'Kill switch activated', 'panic_mode.activated': 'Panic mode activated',
  'bulk_block.executed': 'Bulk block executed', 'playbook.created': 'Playbook created', 'playbook.action_executed': 'Playbook action executed',
}
export default function AuditPage() {
  const navigate = useNavigate()
  const user = useAppStore((state) => state.user)
  const logs = useAppStore((state) => state.auditLogs)
  const [query, setQuery] = useState('')
  const [action, setAction] = useState('all')
  const [userFilter, setUserFilter] = useState('all')
  const uniqueUsers = [...new Set(logs.map((item) => item.userName))]
  const actions = [...new Set(logs.map((item) => item.action))]
  const filtered = useMemo(() => logs.filter((item) => (action === 'all' || item.action === action) && (userFilter === 'all' || item.userName === userFilter) && (!query || `${item.userName} ${item.action} ${item.target} ${JSON.stringify(item.metadata)}`.toLowerCase().includes(query.toLowerCase()))).sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()), [logs, action, userFilter, query])
  const exportLogs = () => { downloadText('netdefender-audit-trail.json', JSON.stringify(filtered, null, 2)); }
  if (user?.role !== 'admin') return <Navigate to="/" replace />

  return <div className="page">
    <PageHeader eyebrow="GOVERNANCE & COMPLIANCE" title="Audit trail" description="A workspace history of administrative actions and security response activity recorded by SOC workflows." actions={<Button variant="secondary" onClick={exportLogs}><Download size={15} /> Export logs</Button>} />
    <div className="audit-compliance-banner"><div className="audit-shield"><Fingerprint size={19} /></div><div><b>Audit logging enabled</b><span>Events are appended by SOC workflows; Supabase row-level security denies client-side edits and deletes.</span></div><span className="audit-integrity"><Shield size={14} /> APPEND-ONLY ACCESS</span></div>
    <div className="audit-stats-row"><div><small>TOTAL EVENTS</small><b>{logs.length.toString().padStart(3, '0')}</b></div><div><small>UNIQUE ACTORS</small><b>{uniqueUsers.length.toString().padStart(2, '0')}</b></div><div><small>LAST EVENT</small><b>{logs[0] ? timeAgo(logs[0].createdAt) : '—'}</b></div><div><small>EDIT POLICY</small><b>Append-only</b></div></div>
    <section className="panel audit-panel"><div className="audit-toolbar"><label className="filter-search"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search actor, target, or metadata" /></label><div className="select-shell"><UserRound size={14} /><select value={userFilter} onChange={(event) => setUserFilter(event.target.value)}><option value="all">All users</option>{uniqueUsers.map((name) => <option key={name}>{name}</option>)}</select><ChevronDown size={13} /></div><div className="select-shell"><Activity size={14} /><select value={action} onChange={(event) => setAction(event.target.value)}><option value="all">All actions</option>{actions.map((item) => <option key={item} value={item}>{actionLabels[item] || item}</option>)}</select><ChevronDown size={13} /></div><span className="audit-filter-count">{filtered.length} events</span></div>
      {filtered.length === 0 ? <EmptyState icon={<Fingerprint size={30} />} title={logs.length > 0 ? 'No audit events match' : 'No audit events yet'} description={logs.length > 0 ? 'Clear the actor, action, or text filters to broaden the audit trail.' : 'Administrative changes and response actions will be recorded here as they happen.'} action={logs.length > 0 ? <Button variant="secondary" onClick={() => { setQuery(''); setAction('all'); setUserFilter('all') }}><X size={14} /> Clear filters</Button> : <Button variant="secondary" onClick={() => navigate('/')}><ArrowUpRight size={14} /> Go to overview</Button>} /> : <div className="table-wrap"><table className="data-table audit-table"><thead><tr><th>ACTOR</th><th>ACTION</th><th>TARGET</th><th>METADATA</th><th>TIMESTAMP</th></tr></thead><tbody>{filtered.map((item) => <tr key={item.id}><td><span className="audit-user-cell"><span>{item.userName.split(' ').map((name) => name[0]).join('')}</span><b>{item.userName}</b></span></td><td><span className="audit-action-cell"><i />{actionLabels[item.action] || item.action}</span><small className="audit-action-code">{item.action}</small></td><td><span className="mono-text audit-target">{item.target}</span></td><td><code className="audit-metadata">{JSON.stringify(item.metadata)}</code></td><td><span className="table-time-stack"><b>{formatTime(item.createdAt, true)}</b><small>{timeAgo(item.createdAt)}</small></span></td></tr>)}</tbody></table></div>}
      <div className="table-footer"><span><Fingerprint size={14} /> Showing <b>{filtered.length}</b> of {logs.length} logged actions</span><span>Client access <b>· No edits or deletes</b></span></div>
    </section>
  </div>
}
