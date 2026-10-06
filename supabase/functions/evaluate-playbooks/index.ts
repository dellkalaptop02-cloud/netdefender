import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.4'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
const validFields = new Set(['severity', 'attack_type', 'source_country', 'protocol'])
const validOperators = new Set(['equals', 'contains', 'greater_than'])
const validActions = new Set(['Block IP', 'Create Incident', 'Send Email', 'Slack Notify'])
const severityRank: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 }
type Condition = { field: 'severity' | 'attack_type' | 'source_country' | 'protocol'; operator: 'equals' | 'contains' | 'greater_than'; value: string }
type AlertRow = Record<string, unknown> & { id: string; severity: string; source_ip: string; attack_type: string; protocol: string }
type PlaybookRow = Record<string, unknown> & { id: string; name: string; trigger_condition: string; actions_json: unknown; enabled: boolean }
type ActionResult = { status: string; completed: boolean; message?: string; [key: string]: unknown }
type ResultMap = Record<string, ActionResult>

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function parseCondition(playbook: PlaybookRow): Condition | null {
  const value = objectValue(playbook.condition_json)
  const field = String(value.field)
  const operator = String(value.operator)
  const conditionValue = value.value === undefined || value.value === null ? '' : String(value.value).trim()
  if (validFields.has(field) && validOperators.has(operator) && conditionValue && (operator !== 'greater_than' || field === 'severity')) {
    return { field: field as Condition['field'], operator: operator as Condition['operator'], value: conditionValue }
  }
  const match = /^(severity|attack_type|source_country|protocol)\s*(=|contains|>)\s*(.+)$/i.exec(String(playbook.trigger_condition || '').trim())
  if (!match) return null
  return {
    field: match[1].toLowerCase() as Condition['field'],
    operator: match[2] === '>' ? 'greater_than' : match[2] === '=' ? 'equals' : 'contains',
    value: match[3].trim(),
  }
}

function conditionMatches(alert: AlertRow, condition: Condition) {
  const actual = String(alert[condition.field] ?? '').trim()
  if (condition.operator === 'equals') return actual.toLowerCase() === condition.value.trim().toLowerCase()
  if (condition.operator === 'contains') return actual.toLowerCase().includes(condition.value.trim().toLowerCase())
  if (condition.field !== 'severity') return false
  const expectedRank = severityRank[condition.value.toLowerCase()]
  const actualRank = severityRank[actual.toLowerCase()]
  return expectedRank !== undefined && actualRank !== undefined && actualRank > expectedRank
}

async function digest(value: string) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(bytes)).map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function appendAudit(db: ReturnType<typeof createClient>, payload: Record<string, unknown>) {
  const { error } = await db.from('audit_logs').upsert(payload, { onConflict: 'id', ignoreDuplicates: true })
  if (error) throw new Error(`Audit event could not be recorded: ${error.message}`)
}

async function syncFirewall(url: string | undefined, token: string | undefined, payload: Record<string, unknown>) {
  if (!url) return 'not_configured'
  try {
    const result = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(payload),
    })
    if (!result.ok) console.error('Automation firewall webhook returned', result.status)
    return result.ok ? 'synced' : 'failed'
  } catch (error) {
    console.error('Automation firewall webhook failed', error)
    return 'failed'
  }
}

async function blockAlertSource(db: ReturnType<typeof createClient>, alert: AlertRow, playbook: PlaybookRow) {
  const ip = String(alert.source_ip || '').trim()
  const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/
  if (!ipv4.test(ip)) throw new Error('The alert source is not a valid IPv4 address; it was not blocked.')
  const reason = `Automated by ${playbook.name}: ${alert.attack_type} (${alert.id})`.slice(0, 160)
  let activeBlock: Record<string, unknown> | null = null
  const { data: existing, error: lookupError } = await db.from('blocked_ips').select('id,expires_at').eq('ip', ip).eq('is_active', true).maybeSingle()
  if (lookupError) throw new Error(`Could not check the existing block list: ${lookupError.message}`)
  if (existing) {
    const expired = Boolean(existing.expires_at) && new Date(String(existing.expires_at)).getTime() <= Date.now()
    if (expired) {
      const { error } = await db.from('blocked_ips').update({ is_active: false }).eq('id', existing.id)
      if (error) throw new Error(`Could not retire an expired block entry: ${error.message}`)
    } else activeBlock = existing
  }

  let created = false
  let blockId = activeBlock ? String(activeBlock.id) : ''
  let firewallSync = 'not_requested'
  if (!activeBlock) {
    blockId = `BLK-${crypto.randomUUID()}`
    const { data, error } = await db.from('blocked_ips').insert({
      id: blockId,
      ip,
      reason,
      blocked_by: 'NetDefender Automation',
      blocked_at: new Date().toISOString(),
      expires_at: null,
      is_active: true,
    }).select('id,ip,reason,blocked_at,expires_at,is_active').single()
    if (error?.code === '23505') {
      const { data: racedBlock, error: raceLookupError } = await db.from('blocked_ips').select('id,expires_at').eq('ip', ip).eq('is_active', true).maybeSingle()
      if (raceLookupError || !racedBlock) throw new Error(`The source IP could not be added to the block list: ${error.message}`)
      activeBlock = racedBlock
      blockId = String(racedBlock.id)
    } else if (error || !data) {
      throw new Error(`The source IP could not be added to the block list: ${error?.message || 'unknown database error'}`)
    } else {
      activeBlock = data
      created = true
    }
  }

  const { data: latestAlert, error: alertLookupError } = await db.from('alerts').select('status').eq('id', alert.id).maybeSingle()
  if (alertLookupError || !latestAlert) {
    if (created) await db.from('blocked_ips').update({ is_active: false }).eq('id', blockId)
    throw new Error('The alert disappeared before its automated block could be applied.')
  }
  const previousStatus = String(latestAlert.status || 'new')
  const { error: alertUpdateError } = await db.from('alerts').update({ status: 'blocked' }).eq('id', alert.id).eq('source_ip', ip)
  if (alertUpdateError) {
    if (created) await db.from('blocked_ips').update({ is_active: false }).eq('id', blockId)
    throw new Error(`The alert status could not be set to blocked: ${alertUpdateError.message}`)
  }

  if (created) {
    firewallSync = await syncFirewall(Deno.env.get('FIREWALL_WEBHOOK_URL'), Deno.env.get('FIREWALL_WEBHOOK_TOKEN'), {
      action: 'block', ip, reason, expires_at: null, request_id: blockId, automation: true,
    })
  }
  const auditId = `AUD-PB-${(await digest(`${playbook.id}:${alert.id}:block`)).slice(0, 36)}`
  try {
    await appendAudit(db, {
      id: auditId,
      user_id: null,
      action: created ? 'blocked_ip.added' : 'playbook.action_executed',
      target: ip,
      metadata: {
        actor: 'NetDefender Automation',
        automated: true,
        action: 'Block IP',
        playbook_id: playbook.id,
        playbook_name: playbook.name,
        alert_id: alert.id,
        reason,
        firewall_sync: firewallSync,
        existing_block: !created,
      },
    })
  } catch (error) {
    await db.from('alerts').update({ status: previousStatus }).eq('id', alert.id)
    if (created) {
      await db.from('blocked_ips').update({ is_active: false }).eq('id', blockId)
      if (firewallSync === 'synced') await syncFirewall(Deno.env.get('FIREWALL_WEBHOOK_URL'), Deno.env.get('FIREWALL_WEBHOOK_TOKEN'), { action: 'unblock', ip, request_id: blockId, automation: true })
    }
    throw error
  }

  return {
    status: created ? 'blocked' : 'already_blocked',
    completed: true,
    block_id: blockId,
    alert_status: 'blocked',
    firewall_sync: firewallSync,
    message: created ? 'Source IP added to the block list and alert marked blocked.' : 'An active block already exists; the alert was marked blocked.',
  } satisfies ActionResult
}

async function createIncident(db: ReturnType<typeof createClient>, alert: AlertRow, playbook: PlaybookRow) {
  const id = `INC-PB-${(await digest(`${playbook.id}:${alert.id}:incident`)).slice(0, 28)}`
  const title = `${alert.attack_type} from ${alert.source_ip}`.slice(0, 240)
  const { error } = await db.from('incidents').insert({
    id,
    title,
    description: `Created automatically by playbook “${playbook.name}” for alert ${alert.id}. Signature: ${String(alert.signature || alert.attack_type)}.`,
    severity: alert.severity,
    status: 'new',
    assigned_to: 'Unassigned',
    notes: [`Source IP: ${alert.source_ip}`, `Protocol: ${alert.protocol}`, `Playbook: ${playbook.name}`],
  })
  const alreadyExists = error?.code === '23505'
  if (error && !alreadyExists) throw new Error(`Incident creation failed: ${error.message}`)
  const auditId = `AUD-PB-${(await digest(`${playbook.id}:${alert.id}:incident-audit`)).slice(0, 36)}`
  await appendAudit(db, {
    id: auditId,
    user_id: null,
    action: alreadyExists ? 'playbook.action_executed' : 'incident.created',
    target: id,
    metadata: { actor: 'NetDefender Automation', automated: true, action: 'Create Incident', playbook_id: playbook.id, playbook_name: playbook.name, alert_id: alert.id },
  })
  return { status: alreadyExists ? 'already_exists' : 'created', completed: true, incident_id: id, message: alreadyExists ? 'The incident for this playbook and alert already exists.' : 'Incident created and audit event recorded.' } satisfies ActionResult
}

async function claimRun(db: ReturnType<typeof createClient>, playbook: PlaybookRow, alert: AlertRow, condition: Condition, actions: string[]) {
  const runId = `PBR-${crypto.randomUUID()}`
  const now = new Date().toISOString()
  const row = {
    id: runId,
    playbook_id: playbook.id,
    alert_id: alert.id,
    status: 'running',
    condition_json: condition,
    actions_json: actions,
    result_json: {},
    error_message: null,
    started_at: now,
    completed_at: null,
  }
  const { data, error } = await db.from('playbook_runs').insert(row).select('id,result_json').single()
  if (!error && data) return { id: String(data.id), results: objectValue(data.result_json) as ResultMap }
  if (error?.code !== '23505') throw new Error(`Could not claim playbook execution: ${error?.message || 'unknown database error'}`)

  const reset = { status: 'running', started_at: now, completed_at: null, error_message: null }
  const { data: failedRun, error: failedError } = await db.from('playbook_runs').update(reset).eq('playbook_id', playbook.id).eq('alert_id', alert.id).eq('status', 'failed').select('id,result_json').maybeSingle()
  if (failedError) throw new Error(`Could not retry the previous playbook run: ${failedError.message}`)
  if (failedRun) return { id: String(failedRun.id), results: objectValue(failedRun.result_json) as ResultMap }

  const staleBefore = new Date(Date.now() - 15 * 60 * 1000).toISOString()
  const { data: staleRun, error: staleError } = await db.from('playbook_runs').update(reset).eq('playbook_id', playbook.id).eq('alert_id', alert.id).eq('status', 'running').lt('started_at', staleBefore).select('id,result_json').maybeSingle()
  if (staleError) throw new Error(`Could not reclaim an expired playbook execution: ${staleError.message}`)
  return staleRun ? { id: String(staleRun.id), results: objectValue(staleRun.result_json) as ResultMap } : null
}

async function saveProgress(db: ReturnType<typeof createClient>, runId: string, results: ResultMap) {
  const { error } = await db.from('playbook_runs').update({ result_json: results }).eq('id', runId).eq('status', 'running')
  if (error) throw new Error(`Could not save action progress: ${error.message}`)
}

async function notifyChannels(url: string, serviceKey: string, alertId: string, channels: Array<'email' | 'slack'>, playbookId: string, includeInApp = false) {
  const result = await fetch(`${url}/functions/v1/send-notification`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${serviceKey}`, apikey: serviceKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ alert_id: alertId, channels, allow_noncritical: true, include_in_app: includeInApp, playbook_id: playbookId }),
  })
  const payload = await result.json().catch(() => ({})) as { ok?: boolean; error?: string; channels?: Record<string, string> }
  if (!result.ok || !payload.ok) throw new Error(payload.error || `Notification service returned HTTP ${result.status}.`)
  return payload.channels || {}
}

async function notifyIntegration(url: string, serviceKey: string, alertId: string, channel: 'email' | 'slack', playbookId: string) {
  const channels = await notifyChannels(url, serviceKey, alertId, [channel], playbookId)
  const state = channels[channel] || 'not_configured'
  if (state === 'failed') throw new Error(`${channel === 'email' ? 'Email' : 'Slack'} delivery failed.`)
  return state
}

async function evaluateOne(db: ReturnType<typeof createClient>, alert: AlertRow, playbook: PlaybookRow, condition: Condition, serviceUrl: string, serviceKey: string, sentChannels: Set<'email' | 'slack'>) {
  const actions = Array.isArray(playbook.actions_json) ? playbook.actions_json.map(String) : []
  const claimed = await claimRun(db, playbook, alert, condition, actions)
  if (!claimed) return { playbook_id: playbook.id, playbook_name: playbook.name, status: 'skipped', reason: 'This alert is already being processed or has completed.' }

  const results = claimed.results
  const errors: string[] = []
  for (const action of actions) {
    const channel = action === 'Send Email' ? 'email' : action === 'Slack Notify' ? 'slack' : null
    const previous = results[action]
    if (previous?.completed) {
      if (channel && previous.status === 'delivered') sentChannels.add(channel)
      continue
    }
    try {
      let outcome: ActionResult
      if (!validActions.has(action)) {
        throw new Error(`Unsupported response action “${action}”.`)
      } else if (action === 'Block IP') {
        outcome = await blockAlertSource(db, alert, playbook)
      } else if (action === 'Create Incident') {
        outcome = await createIncident(db, alert, playbook)
      } else if (channel) {
        if (sentChannels.has(channel)) {
          outcome = { status: 'deduplicated', completed: true, message: `A ${channel} notification was already delivered for this alert.` }
        } else {
          const delivery = await notifyIntegration(serviceUrl, serviceKey, alert.id, channel, playbook.id)
          if (delivery === 'sent') {
            sentChannels.add(channel)
            outcome = { status: 'delivered', completed: true, channel, message: `${channel === 'email' ? 'Email' : 'Slack'} notification delivered.` }
          } else {
            outcome = { status: 'skipped', completed: true, channel, message: `${channel === 'email' ? 'Email' : 'Slack'} integration is not configured.` }
          }
        }
      } else {
        throw new Error(`Unsupported response action “${action}”.`)
      }
      results[action] = outcome
      await saveProgress(db, claimed.id, results)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      results[action] = { status: 'failed', completed: false, message }
      errors.push(`${action}: ${message}`)
      try { await saveProgress(db, claimed.id, results) } catch (progressError) { console.error('Could not persist failed playbook action', progressError) }
    }
  }

  const status = errors.length ? 'failed' : 'succeeded'
  const { error: finishError } = await db.from('playbook_runs').update({ status, result_json: results, error_message: errors.length ? errors.join(' | ').slice(0, 2000) : null, completed_at: new Date().toISOString() }).eq('id', claimed.id)
  if (finishError) console.error('Could not finalize playbook run', claimed.id, finishError)
  return { playbook_id: playbook.id, playbook_name: playbook.name, run_id: claimed.id, status, actions: results, ...(errors.length ? { errors } : {}) }
}

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (request.method !== 'POST') return response({ error: 'Method not allowed.' }, 405)
  try {
    const url = Deno.env.get('SUPABASE_URL')
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')
    if (!url || !serviceKey || !anonKey) return response({ error: 'Supabase service configuration is incomplete.' }, 500)
    const token = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '')
    if (!token) return response({ error: 'Authentication required.' }, 401)
    const db = createClient(url, serviceKey, { auth: { persistSession: false } })
    const internalCall = token === serviceKey
    if (!internalCall) {
      const userClient = createClient(url, anonKey, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false } })
      const { data: authData, error: authError } = await userClient.auth.getUser(token)
      if (authError || !authData.user) return response({ error: 'Invalid session.' }, 401)
      const { data: profile, error: profileError } = await db.from('profiles').select('role').eq('id', authData.user.id).maybeSingle()
      if (profileError || profile?.role !== 'admin') return response({ error: 'Workspace administrator access is required for playbook evaluation.' }, 403)
    }

    let body: Record<string, unknown>
    try { body = await request.json() as Record<string, unknown> } catch { return response({ error: 'A JSON request body is required.' }, 400) }
    const dryRun = body.dry_run === true
    if (dryRun) {
      const playbookId = String(body.playbook_id || '').trim()
      if (!playbookId) return response({ error: 'playbook_id is required for a test run.' }, 400)
      const { data: playbook, error: playbookError } = await db.from('playbooks').select('*').eq('id', playbookId).maybeSingle()
      if (playbookError || !playbook) return response({ error: 'Playbook not found.' }, 404)
      let alertQuery = db.from('alerts').select('*')
      const alertId = String(body.alert_id || '').trim()
      if (alertId) alertQuery = alertQuery.eq('id', alertId)
      else alertQuery = alertQuery.order('timestamp', { ascending: false }).limit(1)
      const { data: alert, error: alertError } = await alertQuery.maybeSingle()
      if (alertError) return response({ error: `Could not load a test alert: ${alertError.message}` }, 500)
      const condition = parseCondition(playbook as PlaybookRow)
      if (!condition) return response({ error: 'This playbook has an invalid condition. Edit and save it before testing.' }, 422)
      const matches = Boolean(alert && conditionMatches(alert as AlertRow, condition))
      return response({
        ok: true,
        dry_run: true,
        playbook_id: playbook.id,
        playbook_name: playbook.name,
        alert_id: alert?.id || null,
        matched: matches,
        condition,
        planned_actions: matches && Array.isArray(playbook.actions_json) ? playbook.actions_json.map(String) : [],
        message: alert ? (matches ? 'Condition matched; no production actions were executed.' : 'Condition did not match; no production actions were executed.') : 'No alerts are available to test.',
      })
    }

    const alertId = String(body.alert_id || '').trim()
    if (!alertId) return response({ error: 'alert_id is required.' }, 400)
    const { data: alert, error: alertError } = await db.from('alerts').select('*').eq('id', alertId).maybeSingle()
    if (alertError || !alert) return response({ error: 'Alert not found.' }, 404)
    const { data: playbooks, error: playbookError } = await db.from('playbooks').select('*').eq('enabled', true).order('created_at', { ascending: true })
    if (playbookError) return response({ error: `Could not load active playbooks: ${playbookError.message}` }, 500)

    const sentChannels = new Set<'email' | 'slack'>()
    const { data: completedRuns, error: completedRunsError } = await db.from('playbook_runs').select('result_json').eq('alert_id', alert.id).eq('status', 'succeeded')
    if (completedRunsError) return response({ error: `Could not check completed playbook runs: ${completedRunsError.message}` }, 500)
    for (const run of completedRuns || []) {
      for (const actionResult of Object.values(objectValue(run.result_json))) {
        const result = objectValue(actionResult)
        if (result.status === 'delivered' && result.channel === 'email') sentChannels.add('email')
        if (result.status === 'delivered' && result.channel === 'slack') sentChannels.add('slack')
      }
    }
    const runs: Record<string, unknown>[] = []
    for (const playbook of (playbooks || []) as PlaybookRow[]) {
      const condition = parseCondition(playbook)
      if (!condition || !conditionMatches(alert as AlertRow, condition)) continue
      try {
        runs.push(await evaluateOne(db, alert as AlertRow, playbook, condition, url, serviceKey, sentChannels))
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        console.error('Playbook evaluation failed', playbook.id, alert.id, message)
        runs.push({ playbook_id: playbook.id, playbook_name: playbook.name, status: 'failed', errors: [message] })
      }
    }

    let criticalNotification: Record<string, unknown> | null = null
    if (String((alert as AlertRow).severity).toLowerCase() === 'critical') {
      const remainingChannels = (['email', 'slack'] as const).filter((channel) => !sentChannels.has(channel))
      try {
        // Keep the legacy in-app alert while delivering each external channel at most once.
        const channels = await notifyChannels(url, serviceKey, alert.id, [...remainingChannels], 'critical-alert-default', true)
        criticalNotification = { channels, in_app: 'requested' }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        console.error('Critical alert notification dispatch failed', alert.id, message)
        criticalNotification = { error: message }
      }
    }

    return response({ ok: true, alert_id: alert.id, matched_playbooks: runs.length, runs, critical_notification: criticalNotification })
  } catch (error) {
    console.error('evaluate-playbooks', error)
    return response({ error: error instanceof Error ? error.message : 'Playbook evaluation failed.' }, 500)
  }
})
