import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.4'

const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
type Channel = 'email' | 'slack'

async function stableId(value: string) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(bytes)).map((byte) => byte.toString(16).padStart(2, '0')).join('').slice(0, 32)
}
function escapeHtml(value: unknown) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character] || character)
}

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (request.method !== 'POST') return response({ error: 'Method not allowed' }, 405)
  try {
    const url = Deno.env.get('SUPABASE_URL')
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
    if (!url || !anonKey || !serviceKey) return response({ error: 'Supabase service configuration is incomplete.' }, 500)
    const authHeader = request.headers.get('authorization') || ''
    const token = authHeader.replace(/^Bearer\s+/i, '')
    if (!token) return response({ error: 'Unauthorized' }, 401)
    const db = createClient(url, serviceKey, { auth: { persistSession: false } })
    if (token !== serviceKey) {
      const userClient = createClient(url, anonKey, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false } })
      const { data: userData } = await userClient.auth.getUser(token)
      if (!userData.user) return response({ error: 'Invalid session' }, 401)
      const { data: profile } = await db.from('profiles').select('role').eq('id', userData.user.id).maybeSingle()
      if (profile?.role !== 'admin') return response({ error: 'Admin role required' }, 403)
    }

    let body: Record<string, unknown>
    try { body = await request.json() as Record<string, unknown> } catch { return response({ error: 'A JSON request body is required.' }, 400) }
    const alertId = body.alert_id
    if (!alertId || typeof alertId !== 'string') return response({ error: 'alert_id is required' }, 400)
    const { data: alert, error } = await db.from('alerts').select('*').eq('id', alertId).single()
    if (error || !alert) return response({ error: 'Alert not found' }, 404)

    const allowNoncritical = body.allow_noncritical === true
    if (String(alert.severity).toLowerCase() !== 'critical' && !allowNoncritical) {
      return response({ ok: true, skipped: 'Only critical alerts trigger the default notification workflow.' })
    }

    let channels: Channel[]
    if (Array.isArray(body.channels)) {
      const requested = body.channels.map(String)
      if (requested.some((channel) => channel !== 'email' && channel !== 'slack')) return response({ error: 'channels may contain only email and slack.' }, 400)
      channels = [...new Set(requested)] as Channel[]
    } else {
      // Preserve the legacy critical-alert behavior for callers that only provide alert_id.
      channels = String(alert.severity).toLowerCase() === 'critical' ? ['email', 'slack'] : []
    }
    const includeInApp = typeof body.include_in_app === 'boolean' ? body.include_in_app : !Array.isArray(body.channels)
    const { data: admins, error: profilesError } = await db.from('profiles').select('id,email').eq('role', 'admin')
    if (profilesError) console.error('Could not load notification recipients', profilesError)
    const recipients = (admins || []).filter((profile) => profile.email).map((profile) => profile.email)
    const isCritical = String(alert.severity).toLowerCase() === 'critical'
    const severityLabel = String(alert.severity || 'security').toUpperCase()
    const title = isCritical ? `Critical ${alert.attack_type} detection` : `${severityLabel} ${alert.attack_type} alert`
    const message = `${alert.source_ip} (${alert.source_country || 'unknown origin'}) targeted ${alert.destination_ip || 'a protected asset'}. Signature: ${alert.signature || alert.attack_type}.`
    let inApp = 'not_requested'
    if (includeInApp) {
      const inserts = await Promise.all((admins || []).map(async (profile) => ({
        id: `NTF-CRIT-${await stableId(`${alert.id}:${profile.id}`)}`,
        user_id: profile.id,
        title,
        message,
        type: 'critical',
        read: false,
      })))
      if (inserts.length) {
        const { error: insertError } = await db.from('notifications').upsert(inserts, { onConflict: 'id', ignoreDuplicates: true })
        if (insertError) {
          inApp = 'failed'
          console.error('Could not persist in-app alert notifications', insertError)
        } else inApp = 'sent'
      } else inApp = 'no_admin_recipients'
    }

    const slackUrl = Deno.env.get('SLACK_WEBHOOK_URL')
    const resendKey = Deno.env.get('RESEND_API_KEY')
    const emailFrom = Deno.env.get('RESEND_FROM_EMAIL') || 'NetDefender SOC <alerts@netdefender.example>'
    const emailTo = recipients.length ? recipients : Deno.env.get('SOC_NOTIFICATION_EMAIL') ? [Deno.env.get('SOC_NOTIFICATION_EMAIL')!] : []
    const delivery: Record<Channel, string> = { email: 'not_requested', slack: 'not_requested' }
    const errors: string[] = []
    const tasks: Promise<void>[] = []

    if (channels.includes('slack')) {
      if (!slackUrl) delivery.slack = 'not_configured'
      else tasks.push((async () => {
        try {
          const result = await fetch(slackUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: `${isCritical ? ':rotating_light:' : ':shield:'} *${title}*\n${message}\nAlert: ${alert.id}` }) })
          delivery.slack = result.ok ? 'sent' : 'failed'
          if (!result.ok) errors.push(`Slack returned HTTP ${result.status}.`)
        } catch (error) {
          delivery.slack = 'failed'
          errors.push(`Slack delivery failed: ${error instanceof Error ? error.message : String(error)}`)
        }
      })())
    }
    if (channels.includes('email')) {
      if (!resendKey || !emailTo.length) delivery.email = 'not_configured'
      else tasks.push((async () => {
        try {
          const result = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { Authorization: `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              from: emailFrom,
              to: emailTo,
              subject: isCritical ? `[CRITICAL] ${title}` : title,
              html: `<h2>${escapeHtml(title)}</h2><p>${escapeHtml(message)}</p><p>Alert ID: <code>${escapeHtml(alert.id)}</code></p><p>Review the event in the NetDefender SOC console.</p>`,
            }),
          })
          delivery.email = result.ok ? 'sent' : 'failed'
          if (!result.ok) errors.push(`Email provider returned HTTP ${result.status}.`)
        } catch (error) {
          delivery.email = 'failed'
          errors.push(`Email delivery failed: ${error instanceof Error ? error.message : String(error)}`)
        }
      })())
    }
    await Promise.all(tasks)
    const failures = Object.values(delivery).filter((state) => state === 'failed').length
    return response({ ok: failures === 0, recipients: emailTo.length, channels: delivery, in_app: inApp, ...(errors.length ? { errors } : {}) }, failures ? 502 : 200)
  } catch (error) {
    console.error('send-notification', error)
    return response({ error: 'Notification delivery failed' }, 500)
  }
})
