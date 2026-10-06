import { useRef, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { Ban, Check, ChevronDown, Download, Fingerprint, LoaderCircle, Plus, Shield, ShieldCheck, Square, Trash2, Upload, Zap } from 'lucide-react'
import { useAppStore } from '../store'
import { downloadText, formatTime } from '../lib/utils'
import { activateFirewallKillSwitch } from '../lib/responseActions'
import type { FirewallRule } from '../types'
import { Button, EmptyState, IconButton, Modal, PageHeader, Toggle } from '../components/Ui'

const ruleSchema = z.object({ name: z.string().min(3, 'Rule name must be at least 3 characters').max(80), action: z.enum(['allow', 'deny']), protocol: z.enum(['ANY', 'TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']), source: z.string().min(1, 'Source is required').max(100), destination: z.string().min(1, 'Destination is required').max(100), port: z.string().min(1, 'Port or ANY is required').max(40) })
type RuleForm = z.infer<typeof ruleSchema>

export default function FirewallPage() {
  const rules = useAppStore((state) => state.firewallRules)
  const user = useAppStore((state) => state.user)
  const addRule = useAppStore((state) => state.addFirewallRule)
  const updateRule = useAppStore((state) => state.updateFirewallRule)
  const removeRule = useAppStore((state) => state.removeFirewallRule)
  const toggleRule = useAppStore((state) => state.toggleFirewallRule)
  const addAuditLog = useAppStore((state) => state.addAuditLog)
  const [modalOpen, setModalOpen] = useState(false)
  const [killOpen, setKillOpen] = useState(false)
  const [killSubmitting, setKillSubmitting] = useState(false)
  const [editing, setEditing] = useState<FirewallRule | null>(null)
  const importRef = useRef<HTMLInputElement>(null)
  const { register, handleSubmit, reset, formState: { errors } } = useForm<RuleForm>({ resolver: zodResolver(ruleSchema), defaultValues: { action: 'deny', protocol: 'TCP', source: '0.0.0.0/0', destination: '10.24.0.0/16', port: 'ANY' } })
  const activeCount = rules.filter((rule) => rule.enabled).length
  const allowCount = rules.filter((rule) => rule.action === 'allow').length
  const denyCount = rules.filter((rule) => rule.action === 'deny').length

  const openNew = () => { setEditing(null); reset({ name: '', action: 'deny', protocol: 'TCP', source: '0.0.0.0/0', destination: '10.24.0.0/16', port: 'ANY' }); setModalOpen(true) }
  const openEdit = (rule: FirewallRule) => { setEditing(rule); reset({ name: rule.name, action: rule.action, protocol: rule.protocol as RuleForm['protocol'], source: rule.source, destination: rule.destination, port: rule.port }); setModalOpen(true) }
  const submit = handleSubmit((values) => {
    if (editing) { updateRule(editing.id, values); toast.success(`Rule “${values.name}” updated`) }
    else { addRule({ ...values, id: `FW-${Date.now().toString().slice(-5)}`, enabled: true, createdBy: user?.fullName || 'SOC Operator', createdAt: new Date().toISOString() }); toast.success(`Rule “${values.name}” created`) }
    addAuditLog({ id: `AUD-${Date.now()}`, userId: user?.id || 'demo', userName: user?.fullName || 'SOC Operator', action: editing ? 'firewall_rule.updated' : 'firewall_rule.created', target: values.name, metadata: { action: values.action }, createdAt: new Date().toISOString() })
    setModalOpen(false); setEditing(null); reset()
  })
  const handleToggle = (rule: FirewallRule) => { toggleRule(rule.id); addAuditLog({ id: `AUD-${Date.now()}`, userId: user?.id || 'demo', userName: user?.fullName || 'SOC Operator', action: 'firewall_rule.toggled', target: rule.id, metadata: { enabled: !rule.enabled }, createdAt: new Date().toISOString() }); toast.success(`${rule.name} ${rule.enabled ? 'disabled' : 'enabled'}`) }
  const deleteRule = (rule: FirewallRule) => { if (window.confirm(`Delete “${rule.name}”?`)) { removeRule(rule.id); toast.success('Firewall rule deleted') } }
  const killSwitch = async () => {
    if (killSubmitting || user?.role !== 'admin') return
    setKillSubmitting(true)
    try {
      const result = await activateFirewallKillSwitch(user, 'firewall')
      setKillOpen(false)
      if (result.auditLogged) toast.error('Kill switch activated', { description: `${result.disabledRules} enabled policies disabled. The action was recorded in the audit trail.` })
      else toast.error('Firewall disabled with an audit warning', { description: `Rules are disabled, but the audit entry could not be saved: ${result.auditError}` })
    } catch (error) {
      toast.error('Kill switch failed', { description: error instanceof Error ? error.message : 'Firewall rules could not be disabled.' })
    } finally { setKillSubmitting(false) }
  }
  const exportJson = () => { downloadText('netdefender-firewall-rules.json', JSON.stringify(rules, null, 2)); toast.success(`${rules.length} firewall rules exported`) }
  const importJson = (file?: File) => {
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      try {
        const values = JSON.parse(String(reader.result)) as unknown
        if (!Array.isArray(values)) throw new Error('JSON must contain an array of rules.')
        const valid = values.map((value, index) => {
          const result = ruleSchema.safeParse(value)
          if (!result.success) throw new Error(`Rule ${index + 1}: ${result.error.issues[0].message}`)
          return { ...result.data, id: `FW-${Date.now()}-${index}`, enabled: (value as { enabled?: boolean }).enabled ?? true, createdBy: user?.fullName || 'Imported', createdAt: new Date().toISOString() } satisfies FirewallRule
        })
        valid.forEach(addRule); toast.success(`${valid.length} rule${valid.length === 1 ? '' : 's'} imported successfully`)
      } catch (error) { toast.error('Import failed', { description: error instanceof Error ? error.message : 'Invalid JSON file.' }) }
      if (importRef.current) importRef.current.value = ''
    }
    reader.readAsText(file)
  }

  return <div className="page">
    <PageHeader eyebrow="NETWORK POLICY" title="Firewall rules" description="Define and enforce policy at the network perimeter. Changes sync to connected sensors." actions={<>{user?.role === 'admin' && <Button variant="secondary" onClick={() => importRef.current?.click()}><Upload size={15} /> Import JSON</Button>}<Button variant="secondary" onClick={exportJson}><Download size={15} /> Export JSON</Button>{user?.role === 'admin' && <Button onClick={openNew}><Plus size={16} /> Add rule</Button>}<input ref={importRef} className="visually-hidden" type="file" accept="application/json,.json" onChange={(event) => importJson(event.target.files?.[0])} /></>} />
    <div className="firewall-stats"><div className="firewall-stat-card"><span className="firewall-stat-icon firewall-icon-cyan"><Shield size={18} /></span><div><small>TOTAL POLICIES</small><b>{rules.length.toString().padStart(2, '0')}</b><span>Across all network zones</span></div></div><div className="firewall-stat-card"><span className="firewall-stat-icon firewall-icon-green"><ShieldCheck size={18} /></span><div><small>ACTIVE RULES</small><b>{activeCount.toString().padStart(2, '0')}</b><span>Enforced right now</span></div></div><div className="firewall-stat-card"><span className="firewall-stat-icon firewall-icon-red"><Ban size={18} /></span><div><small>DENY POLICIES</small><b>{denyCount.toString().padStart(2, '0')}</b><span>Threat prevention rules</span></div></div><div className="firewall-stat-card"><span className="firewall-stat-icon firewall-icon-blue"><Zap size={18} /></span><div><small>ALLOW POLICIES</small><b>{allowCount.toString().padStart(2, '0')}</b><span>Trusted network traffic</span></div></div></div>
    <div className="firewall-warning-banner"><div className="warning-banner-icon"><Fingerprint size={18} /></div><div><b>Policy engine operational</b><span>Last policy sync completed 24 seconds ago · 5 sensors synchronized</span></div><span className="sync-health"><i className="pulse-dot" /> SYNCED</span>{user?.role === 'admin' && <Button variant="danger" size="sm" onClick={() => setKillOpen(true)}><Square size={13} fill="currentColor" /> Kill switch</Button>}</div>
    <section className="panel firewall-table-panel"><div className="firewall-panel-heading"><div><h2>Network access policies</h2><p>Rules are evaluated top to bottom. Drag to reorder policies.</p></div><span className="policy-count"><span className="pulse-dot" /> {activeCount} ACTIVE</span></div>
      {rules.length === 0 ? <EmptyState icon={<Shield size={30} />} title="No firewall rules yet" description="Add your first network policy to control inbound and outbound traffic. Viewers can ask a workspace administrator to create one." action={user?.role === 'admin' ? <Button onClick={openNew}><Plus size={15} /> Add first rule</Button> : undefined} /> : <div className="table-wrap"><table className="data-table firewall-table"><thead><tr><th>PRIORITY</th><th>NAME</th><th>ACTION</th><th>PROTOCOL</th><th>SOURCE</th><th>DESTINATION</th><th>PORT</th><th>ENABLED</th><th></th></tr></thead><tbody>{rules.map((rule, index) => <tr key={rule.id}><td><span className="priority-number">{String(index + 1).padStart(2, '0')}</span></td><td><button className="rule-name-button" disabled={user?.role !== 'admin'} onClick={() => openEdit(rule)}><span className={`rule-action-icon ${rule.action === 'deny' ? 'rule-deny' : 'rule-allow'}`}>{rule.action === 'deny' ? <Ban size={14} /> : <Check size={14} />}</span><span><b>{rule.name}</b><small>{rule.id} · {rule.createdBy}</small></span></button></td><td><span className={`action-badge action-${rule.action}`}>{rule.action === 'deny' ? <Ban size={12} /> : <Check size={12} />}{rule.action.toUpperCase()}</span></td><td><span className="protocol-badge">{rule.protocol}</span></td><td><span className="mono-text rule-network">{rule.source}</span></td><td><span className="mono-text rule-network">{rule.destination}</span></td><td><span className="port-pill">{rule.port}</span></td><td><Toggle checked={rule.enabled} onChange={() => handleToggle(rule)} label={`Toggle ${rule.name}`} disabled={user?.role !== 'admin'} /></td><td><div className="rule-actions"><IconButton label="Edit rule" disabled={user?.role !== 'admin'} onClick={() => openEdit(rule)}><Square size={13} /></IconButton><IconButton label="Delete rule" disabled={user?.role !== 'admin'} onClick={() => deleteRule(rule)}><Trash2 size={14} /></IconButton></div></td></tr>)}</tbody></table></div>}
      <div className="table-footer"><span><ShieldCheck size={14} /> Policy evaluation latency <b>3.2ms</b></span><span>Updated <b>{formatTime(new Date())}</b> <span className="section-subtle-separator">·</span> {activeCount} of {rules.length} policies enabled</span></div>
    </section>
    <Modal open={modalOpen} onClose={() => { setModalOpen(false); setEditing(null); reset() }} title={editing ? 'Edit firewall rule' : 'Create firewall rule'} subtitle="Define a network access policy. Rules sync to all connected sensors." size="md" footer={<><Button variant="ghost" onClick={() => { setModalOpen(false); setEditing(null); reset() }}>Cancel</Button><Button onClick={submit}><Check size={15} /> {editing ? 'Save changes' : 'Create rule'}</Button></>}>
      <form className="form-stack" onSubmit={submit}><label className="form-field"><span>Rule name <b>*</b></span><input placeholder="e.g. Block suspicious outbound traffic" {...register('name')} />{errors.name && <small className="field-error">{errors.name.message}</small>}</label>
        <div className="form-two-column"><label className="form-field"><span>Action <b>*</b></span><div className="select-input"><select {...register('action')}><option value="deny">Deny traffic</option><option value="allow">Allow traffic</option></select><ChevronDown size={14} /></div></label><label className="form-field"><span>Protocol</span><div className="select-input"><select {...register('protocol')}><option>TCP</option><option>UDP</option><option>ICMP</option><option>HTTP</option><option>HTTPS</option><option>ANY</option></select><ChevronDown size={14} /></div></label></div>
        <div className="form-two-column"><label className="form-field"><span>Source CIDR / IP <b>*</b></span><input className="mono-text" placeholder="0.0.0.0/0" {...register('source')} />{errors.source && <small className="field-error">{errors.source.message}</small>}</label><label className="form-field"><span>Destination CIDR / IP <b>*</b></span><input className="mono-text" placeholder="10.24.0.0/16" {...register('destination')} />{errors.destination && <small className="field-error">{errors.destination.message}</small>}</label></div>
        <label className="form-field"><span>Destination port</span><input className="mono-text" placeholder="443 or ANY" {...register('port')} />{errors.port && <small className="field-error">{errors.port.message}</small>}</label>
        <div className="form-security-note"><ShieldCheck size={16} /><span>Changes take effect on all healthy sensors after policy synchronization.</span></div>
      </form>
    </Modal>
    <Modal open={killOpen} onClose={() => { if (!killSubmitting) setKillOpen(false) }} title="Disable all firewall rules?" subtitle="Emergency kill switch · High impact action" size="sm" footer={<><Button variant="ghost" onClick={() => setKillOpen(false)} disabled={killSubmitting}>Cancel</Button><Button variant="danger" onClick={() => void killSwitch()} disabled={killSubmitting}>{killSubmitting ? <LoaderCircle className="spin" size={14} /> : <Square size={13} fill="currentColor" />} Disable all rules</Button></>}><div className="kill-switch-copy"><span><Zap size={21} /></span><p>This will immediately disable <strong>{activeCount} enabled firewall policies</strong>. Network traffic will no longer be filtered by these rules. The kill-switch action is recorded in the audit trail.</p></div></Modal>
  </div>
}
