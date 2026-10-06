import { useState } from 'react'
import { z } from 'zod'
import { toast } from 'sonner'
import { Activity, ArrowRight, Ban, BellRing, Check, ChevronDown, CirclePlay, Clock3, Code2, FilePlus2, LoaderCircle, Mail, MessageSquare, Plus, ShieldAlert, Workflow, X } from 'lucide-react'
import { useAppStore } from '../store'
import { formatTime } from '../lib/utils'
import { supabase } from '../lib/supabase'
import type { Alert, Playbook, PlaybookCondition, PlaybookField, PlaybookOperator, Severity } from '../types'
import { Button, EmptyState, Modal, PageHeader, Toggle } from '../components/Ui'

const actionOptions = [
  { id: 'Block IP', label: 'Block source IP', icon: Ban, detail: 'Add source to deny list' },
  { id: 'Create Incident', label: 'Create incident', icon: FilePlus2, detail: 'Open a SOC response case' },
  { id: 'Send Email', label: 'Send email', icon: Mail, detail: 'Notify the on-call analyst' },
  { id: 'Slack Notify', label: 'Slack notification', icon: MessageSquare, detail: 'Post to security channel' },
]
const playbookSchema = z.object({
  name: z.string().trim().min(3, 'Name must be at least 3 characters'),
  field: z.enum(['severity', 'attack_type', 'source_country', 'protocol']),
  operator: z.enum(['equals', 'contains', 'greater_than']),
  value: z.string().trim().min(1, 'Choose a trigger value'),
  actions: z.array(z.string()).min(1, 'Select at least one response action'),
})
const severityRank: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 }
const fieldLabels: Record<PlaybookField, string> = { severity: 'Alert severity', attack_type: 'Attack type', source_country: 'Source country', protocol: 'Protocol' }
const operatorLabels: Record<PlaybookOperator, string> = { equals: '=', contains: 'contains', greater_than: '>' }

type RunLog = {
  id: string
  playbook_id: string
  alert_id: string
  status: 'running' | 'succeeded' | 'failed'
  actions_json: unknown
  result_json: unknown
  error_message: string | null
  started_at: string
  completed_at: string | null
}

function conditionMatches(alert: Alert, condition: PlaybookCondition) {
  const actual = ({ severity: alert.severity, attack_type: alert.attackType, source_country: alert.sourceCountry, protocol: alert.protocol })[condition.field]
  if (condition.operator === 'equals') return actual.trim().toLowerCase() === condition.value.trim().toLowerCase()
  if (condition.operator === 'contains') return actual.toLowerCase().includes(condition.value.trim().toLowerCase())
  if (condition.field !== 'severity') return false
  const expected = condition.value.toLowerCase() as Severity
  return expected in severityRank && severityRank[alert.severity] > severityRank[expected]
}

function conditionFromLegacy(playbook: Playbook): PlaybookCondition {
  if (playbook.condition) return playbook.condition
  const match = /^(severity|attack_type|source_country|protocol)\s*(=|contains|>)\s*(.+)$/i.exec(playbook.triggerCondition || '')
  if (!match) return { field: 'severity', operator: 'equals', value: '__legacy_unparsed__' }
  return { field: match[1].toLowerCase() as PlaybookField, operator: match[2] === '>' ? 'greater_than' : match[2] === '=' ? 'equals' : 'contains', value: match[3].trim() }
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'Unexpected error. Please try again.'
}

function describeRunResult(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return 'No action details recorded.'
  const entries = Object.entries(value as Record<string, unknown>)
  if (!entries.length) return 'No action details recorded.'
  return entries.map(([action, detail]) => {
    const item = detail && typeof detail === 'object' ? detail as Record<string, unknown> : {}
    const status = String(item.status || 'complete').replaceAll('_', ' ')
    return `${action}: ${status}${item.message ? ` · ${String(item.message)}` : ''}`
  }).join(' · ')
}

export default function PlaybooksPage() {
  const playbooks = useAppStore((state) => state.playbooks)
  const alerts = useAppStore((state) => state.alerts)
  const togglePlaybook = useAppStore((state) => state.togglePlaybook)
  const addPlaybook = useAppStore((state) => state.addPlaybook)
  const user = useAppStore((state) => state.user)
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [field, setField] = useState<PlaybookField>('severity')
  const [operator, setOperator] = useState<PlaybookOperator>('equals')
  const [value, setValue] = useState('critical')
  const [actions, setActions] = useState<string[]>([])
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const [testingId, setTestingId] = useState<string | null>(null)
  const [filter, setFilter] = useState<'all' | 'active' | 'paused'>('all')
  const [logsOpen, setLogsOpen] = useState(false)
  const [logsLoading, setLogsLoading] = useState(false)
  const [logsError, setLogsError] = useState('')
  const [logs, setLogs] = useState<RunLog[]>([])
  const enabledCount = playbooks.filter((item) => item.enabled).length
  const visible = playbooks.filter((item) => filter === 'all' || (filter === 'active' ? item.enabled : !item.enabled))
  const toggleAction = (action: string) => {
    setActions((items) => items.includes(action) ? items.filter((item) => item !== action) : [...items, action])
    setErrors((current) => ({ ...current, actions: '' }))
  }

  const resetBuilder = () => {
    setOpen(false)
    setName('')
    setActions([])
    setErrors({})
    setField('severity')
    setOperator('equals')
    setValue('critical')
    setSaving(false)
  }

  const createPlaybook = async () => {
    const result = playbookSchema.safeParse({ name, field, operator, value, actions })
    if (!result.success) {
      setErrors(Object.fromEntries(result.error.issues.map((issue) => [String(issue.path[0]), issue.message])))
      return
    }
    if (operator === 'greater_than' && field !== 'severity') {
      setErrors({ operator: 'Greater than is only supported for alert severity.' })
      return
    }
    const condition: PlaybookCondition = { field: result.data.field, operator: result.data.operator, value: result.data.value }
    const triggerCondition = `${condition.field} ${operatorLabels[condition.operator]} ${condition.value}`
    const record: Playbook = {
      id: `PB-${crypto.randomUUID()}`,
      name: result.data.name,
      triggerCondition,
      condition,
      actions: result.data.actions,
      enabled: true,
      createdAt: new Date().toISOString(),
    }
    setSaving(true)
    try {
      await addPlaybook(record)
      toast.success('Automation playbook saved', { description: `Now monitoring for ${triggerCondition}.` })
      resetBuilder()
    } catch (error) {
      setSaving(false)
      toast.error('Playbook was not saved', { description: errorMessage(error) })
    }
  }

  const toggle = async (playbook: Playbook) => {
    try {
      await togglePlaybook(playbook.id)
      toast.success(`${playbook.name} ${playbook.enabled ? 'paused' : 'activated'}`)
    } catch (error) {
      toast.error('Could not update playbook', { description: errorMessage(error) })
    }
  }

  const runNow = async (playbook: Playbook) => {
    setTestingId(playbook.id)
    try {
      if (supabase) {
        const { data, error } = await supabase.functions.invoke('evaluate-playbooks', { body: { dry_run: true, playbook_id: playbook.id } })
        const response = data as { ok?: boolean; matched?: boolean; alert_id?: string; planned_actions?: string[]; message?: string } | null
        if (error || !response?.ok) throw new Error(response?.message || error?.message || 'Test run could not be completed.')
        if (!response.alert_id) toast.info(`No recent alert to test “${playbook.name}”`, { description: 'Create or ingest an alert, then run this safe preview again.' })
        else if (response.matched) toast.success(`Test matched alert ${response.alert_id}`, { description: `Dry run only · ${response.planned_actions?.join(', ') || 'No actions selected'}` })
        else toast.info(`No match for alert ${response.alert_id}`, { description: 'The condition was checked; no production actions were taken.' })
      } else {
        const latestAlert = alerts[0]
        if (!latestAlert) toast.info('No recent alert is available to test.')
        else if (conditionMatches(latestAlert, conditionFromLegacy(playbook))) toast.success(`Test matched alert ${latestAlert.id}`, { description: `Dry run only · ${playbook.actions.join(', ') || 'No actions selected'}` })
        else toast.info(`No match for alert ${latestAlert.id}`, { description: 'The condition was checked; no production actions were taken.' })
      }
    } catch (error) {
      toast.error('Test run failed', { description: errorMessage(error) })
    } finally {
      setTestingId(null)
    }
  }

  const showExecutionLogs = async () => {
    setLogsOpen(true)
    setLogsLoading(true)
    setLogsError('')
    setLogs([])
    if (!supabase) {
      setLogsLoading(false)
      setLogsError('Execution logs are available after connecting a Supabase project and applying the playbook-runs migration.')
      return
    }
    try {
      const { data, error } = await supabase.from('playbook_runs').select('id, playbook_id, alert_id, status, actions_json, result_json, error_message, started_at, completed_at').order('started_at', { ascending: false }).limit(100)
      if (error) throw error
      setLogs((data || []) as RunLog[])
    } catch (error) {
      setLogsError(errorMessage(error))
    } finally {
      setLogsLoading(false)
    }
  }

  const useCriticalTemplate = () => {
    setName('Auto-block critical alerts')
    setField('severity')
    setOperator('equals')
    setValue('critical')
    setActions(['Block IP', 'Create Incident'])
    setErrors({})
    setOpen(true)
  }

  return <div className="page">
    <PageHeader eyebrow="AUTOMATED RESPONSE" title="Response playbooks" description="Orchestrate fast, consistent responses when detections meet your criteria." actions={<>{user?.role === 'admin' && <Button variant="secondary" onClick={showExecutionLogs}><Code2 size={15} /> View execution logs</Button>}{user?.role === 'admin' && <Button onClick={() => setOpen(true)}><Plus size={16} /> Create playbook</Button>}</>} />
    <div className="playbook-hero"><div className="playbook-hero-orbit orbit-one" /><div className="playbook-hero-orbit orbit-two" /><div className="playbook-hero-icon"><Workflow size={22} /></div><div className="playbook-hero-copy"><span>SECURITY ORCHESTRATION</span><h2>Turn signals into action.</h2><p>Automate containment and response using policy-driven workflows that run the moment a threat is detected.</p></div><div className="playbook-hero-metrics"><div><strong>{enabledCount}</strong><span>active playbooks</span></div><span className="hero-metric-divider" /><div><strong>98.4<span>%</span></strong><span>automation success</span></div></div><div className="playbook-hero-bg"><i /><i /><i /><i /><i /></div></div>
    <div className="playbook-list-toolbar"><div><h2>Automation library <span>{playbooks.length}</span></h2><p>Manage your response policies and triggers.</p></div><div className="segmented-control"><button className={filter === 'all' ? 'selected' : ''} onClick={() => setFilter('all')}>All playbooks</button><button className={filter === 'active' ? 'selected' : ''} onClick={() => setFilter('active')}>Active</button><button className={filter === 'paused' ? 'selected' : ''} onClick={() => setFilter('paused')}>Paused</button></div></div>
    <div className="playbook-list">{visible.map((playbook) => <article className={`playbook-card ${playbook.enabled ? '' : 'playbook-card-paused'}`} key={playbook.id}>
      <div className={`playbook-card-icon ${playbook.enabled ? '' : 'playbook-paused-icon'}`}><ShieldAlert size={19} /></div><div className="playbook-card-main"><div className="playbook-title-line"><h3>{playbook.name}</h3><span className={`playbook-state ${playbook.enabled ? 'playbook-state-on' : ''}`}><i />{playbook.enabled ? 'ACTIVE' : 'PAUSED'}</span></div><p>Triggered when <code>{playbook.triggerCondition}</code></p><div className="playbook-actions-row"><span>RESPONSE ACTIONS</span>{playbook.actions.map((action) => { const item = actionOptions.find((option) => option.id === action); const ActionIcon = item?.icon || Check; return <span className="playbook-action-chip" key={action}><ActionIcon size={12} /> {action}</span> })}</div></div><div className="playbook-card-meta"><span><Clock3 size={13} /> Updated {formatTime(playbook.createdAt, true)}</span><button className="run-playbook-button" onClick={() => void runNow(playbook)} disabled={testingId === playbook.id}>{testingId === playbook.id ? <LoaderCircle className="spin" size={15} /> : <CirclePlay size={15} />} Test run</button></div><div className="playbook-toggle-area"><span>{playbook.enabled ? 'ON' : 'OFF'}</span><Toggle checked={playbook.enabled} onChange={() => void toggle(playbook)} label={`Toggle ${playbook.name}`} disabled={user?.role !== 'admin'} /></div>
    </article>)}{visible.length === 0 && <EmptyState icon={<Workflow size={30} />} title={playbooks.length > 0 ? 'No playbooks match this filter' : 'No response playbooks yet'} description={playbooks.length > 0 ? 'Show all playbooks or switch filters to find another automation.' : 'Create a rule-based workflow to automate containment, incident creation, and notifications.'} action={<>{playbooks.length > 0 && <Button variant="secondary" onClick={() => setFilter('all')}><X size={14} /> Show all playbooks</Button>}{user?.role === 'admin' && <Button onClick={() => setOpen(true)}><Plus size={15} /> Create playbook</Button>}</>} />}</div>
    <div className="playbook-cta"><div className="playbook-cta-icon"><BellRing size={18} /></div><div><b>Make response repeatable</b><span>Start with a tested critical-alert workflow, then tailor the condition and actions.</span></div>{user?.role === 'admin' && <Button variant="secondary" size="sm" onClick={useCriticalTemplate}>Use critical-alert template <ArrowRight size={14} /></Button>}</div>
    <Modal open={open} onClose={resetBuilder} title="Create response playbook" subtitle="Set a detection condition and choose one or more response actions." size="lg" footer={<><Button variant="ghost" onClick={resetBuilder} disabled={saving}>Cancel</Button><Button onClick={() => void createPlaybook()} disabled={saving}>{saving ? <LoaderCircle className="spin" size={15} /> : <Check size={15} />} Save playbook</Button></>}>
      <div className="playbook-builder"><label className="form-field"><span>Playbook name <b>*</b></span><input placeholder="e.g. Contain high-confidence threats" value={name} onChange={(event) => { setName(event.target.value); setErrors((current) => ({ ...current, name: '' })) }} />{errors.name && <small className="field-error">{errors.name}</small>}</label>
        <div className="builder-step"><div className="builder-step-heading"><span className="builder-step-number">1</span><div><b>IF this alert condition is met</b><small>Choose the field and matching criteria.</small></div></div><div className="condition-row"><div className="select-input"><select value={field} onChange={(event) => { const selected = event.target.value as PlaybookField; setField(selected); setValue(selected === 'severity' ? 'critical' : ''); if (selected !== 'severity' && operator === 'greater_than') setOperator('equals') }} aria-label="Condition field">{Object.entries(fieldLabels).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select><ChevronDown size={14} /></div><div className="select-input condition-operator"><select value={operator} onChange={(event) => { setOperator(event.target.value as PlaybookOperator); setErrors((current) => ({ ...current, operator: '' })) }} aria-label="Condition operator"><option value="equals">equals</option><option value="contains">contains</option><option value="greater_than" disabled={field !== 'severity'}>greater than</option></select><ChevronDown size={14} /></div>{field === 'severity' ? <div className="select-input"><select value={value} onChange={(event) => { setValue(event.target.value); setErrors((current) => ({ ...current, value: '' })) }} aria-label="Severity value"><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><ChevronDown size={14} /></div> : <input className="condition-value" aria-label="Condition value" placeholder="Enter matching value" value={value} onChange={(event) => { setValue(event.target.value); setErrors((current) => ({ ...current, value: '' })) }} />}</div>{errors.operator && <small className="field-error">{errors.operator}</small>}{errors.value && <small className="field-error">{errors.value}</small>}</div>
        <div className="builder-step"><div className="builder-step-heading"><span className="builder-step-number builder-step-number-green">2</span><div><b>THEN perform these actions</b><small>Pick all actions to run when a match occurs.</small></div></div><div className="action-option-grid">{actionOptions.map((action) => { const ActionIcon = action.icon; const active = actions.includes(action.id); return <button type="button" className={`action-option ${active ? 'action-option-selected' : ''}`} key={action.id} onClick={() => toggleAction(action.id)} aria-pressed={active}><span className="action-option-icon"><ActionIcon size={16} /></span><span><b>{action.label}</b><small>{action.detail}</small></span><span className={`action-option-check ${active ? 'checked' : ''}`}>{active && <Check size={12} />}</span></button> })}</div>{errors.actions && <small className="field-error">{errors.actions}</small>}</div>
        <div className="playbook-test-note"><Activity size={15} /><span>New playbooks are enabled immediately. Network blocks and incident creation are recorded in the audit trail.</span></div>
      </div>
    </Modal>
    <Modal open={logsOpen} onClose={() => setLogsOpen(false)} title="Playbook execution logs" subtitle="Recent automated response runs and per-action outcomes." size="lg">
      {logsLoading ? <div className="playbook-log-state"><LoaderCircle className="spin" size={18} /> Loading execution history…</div> : logsError ? <div className="playbook-log-state playbook-log-error"><X size={17} /> {logsError}</div> : logs.length === 0 ? <div className="playbook-log-state playbook-log-empty"><Clock3 size={23} /><div><b>No executions recorded yet</b><span>New matching alerts will appear here after an automation runs.</span></div><Button variant="secondary" size="sm" onClick={() => { setLogsOpen(false); setOpen(true) }}><Plus size={14} /> Create playbook</Button></div> : <div className="playbook-run-list">{logs.map((run) => {
        const playbook = playbooks.find((item) => item.id === run.playbook_id)
        return <article className="playbook-run-row" key={run.id}><div className={`playbook-run-status status-${run.status}`}><i />{run.status}</div><div className="playbook-run-main"><b>{playbook?.name || run.playbook_id}</b><span>Alert <code>{run.alert_id}</code> · {formatTime(run.started_at, true)}</span><small>{describeRunResult(run.result_json)}{run.error_message ? ` · Error: ${run.error_message}` : ''}</small></div><span className="playbook-run-actions">{Array.isArray(run.actions_json) ? run.actions_json.length : 0} actions</span></article>
      })}</div>}
    </Modal>
  </div>
}
