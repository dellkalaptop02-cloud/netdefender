import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.4'

const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }
const respond = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/

type BlockAction = 'block' | 'unblock'
async function syncFirewall(url: string | undefined, token: string | undefined, payload: Record<string, unknown>) {
  if (!url) return 'not_configured'
  try {
    const result = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(payload) })
    if (!result.ok) console.error('Firewall API returned', result.status)
    return result.ok ? 'synced' : 'failed'
  } catch (error) {
    console.error('Firewall API request failed', error)
    return 'failed'
  }
}

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (request.method !== 'POST') return respond({ error: 'Method not allowed' }, 405)
  try {
    const url = Deno.env.get('SUPABASE_URL')!
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const token = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '')
    if (!token) return respond({ error: 'Authentication required.' }, 401)
    const userClient = createClient(url, anonKey, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false } })
    const { data: authData, error: authError } = await userClient.auth.getUser(token)
    if (authError || !authData.user) return respond({ error: 'Invalid session.' }, 401)
    const { data: profile } = await userClient.from('profiles').select('role, full_name').eq('id', authData.user.id).maybeSingle()
    if (profile?.role !== 'admin') return respond({ error: 'Only workspace admins can change network blocks.' }, 403)

    const body = await request.json()
    const ip = String(body.ip || '').trim()
    const action: BlockAction = body.action === 'unblock' ? 'unblock' : 'block'
    const db = createClient(url, serviceKey, { auth: { persistSession: false } })
    const firewallUrl = Deno.env.get('FIREWALL_WEBHOOK_URL')
    const firewallToken = Deno.env.get('FIREWALL_WEBHOOK_TOKEN')
    if (!ipv4.test(ip)) return respond({ error: 'A valid IPv4 address is required.' }, 400)

    if (action === 'unblock') {
      const recordId = String(body.id || '')
      const query = db.from('blocked_ips').update({ is_active: false }).eq('ip', ip).eq('is_active', true)
      if (recordId) query.eq('id', recordId)
      const { data: released, error: releaseError } = await query.select('id,ip,reason').maybeSingle()
      if (releaseError || !released) return respond({ error: 'Active block entry not found.' }, 404)
      const firewallSync = await syncFirewall(firewallUrl, firewallToken, { action: 'unblock', ip, request_id: released.id })
      const auditId = `AUD-${crypto.randomUUID()}`
      const { error: auditError } = await db.from('audit_logs').insert({ id: auditId, user_id: authData.user.id, action: 'blocked_ip.removed', target: ip, metadata: { reason: released.reason, firewall_sync: firewallSync } })
      if (auditError) {
        console.error('Could not write unblock audit event', auditError)
        await db.from('blocked_ips').update({ is_active: true }).eq('id', released.id)
        if (firewallSync === 'synced') await syncFirewall(firewallUrl, firewallToken, { action: 'block', ip, reason: released.reason, request_id: released.id })
        return respond({ error: 'Unblock was rolled back because its audit event could not be recorded.' }, 500)
      }
      return respond({ ok: true, block: released, firewall_sync: firewallSync, audit_id: auditId })
    }

    const reason = String(body.reason || '').trim()
    if (reason.length < 3 || reason.length > 160) return respond({ error: 'Reason must be between 3 and 160 characters.' }, 400)
    const expiresAt = body.expires_at ? new Date(body.expires_at) : null
    if (expiresAt && Number.isNaN(expiresAt.getTime())) return respond({ error: 'Invalid expiration timestamp.' }, 400)
    if (expiresAt && expiresAt.getTime() <= Date.now()) return respond({ error: 'Expiration must be in the future.' }, 400)

    const alertId = String(body.alert_id || '').trim()
    let sourceAlert: { id: string; source_ip: string; status: string } | null = null
    if (alertId) {
      const { data, error } = await db.from('alerts').select('id,source_ip,status').eq('id', alertId).maybeSingle()
      if (error || !data) return respond({ error: 'The source alert no longer exists.' }, 404)
      if (data.source_ip !== ip) return respond({ error: 'The alert source IP does not match the requested block.' }, 400)
      sourceAlert = data
    }

    const { data: existing, error: existingError } = await db.from('blocked_ips').select('id,expires_at').eq('ip', ip).eq('is_active', true).maybeSingle()
    if (existingError) return respond({ error: 'Could not check current block state.' }, 500)
    if (existing) {
      const expired = Boolean(existing.expires_at) && new Date(existing.expires_at).getTime() <= Date.now()
      if (!expired) return respond({ error: 'This address is already actively blocked.' }, 409)
      const { error: expireError } = await db.from('blocked_ips').update({ is_active: false }).eq('id', existing.id)
      if (expireError) return respond({ error: 'Could not refresh the expired block entry.' }, 500)
    }

    const row = { id: `BLK-${crypto.randomUUID()}`, ip, reason, blocked_by: profile.full_name || authData.user.email || 'SOC admin', blocked_at: new Date().toISOString(), expires_at: expiresAt?.toISOString() || null, is_active: true }
    const { data, error } = await db.from('blocked_ips').insert(row).select('*').single()
    if (error) return respond({ error: error.code === '23505' ? 'This address is already actively blocked.' : 'Block action failed.', detail: error.message }, error.code === '23505' ? 409 : 500)

    if (sourceAlert) {
      const { error: alertError } = await db.from('alerts').update({ status: 'blocked' }).eq('id', sourceAlert.id).eq('source_ip', ip)
      if (alertError) {
        await db.from('blocked_ips').update({ is_active: false }).eq('id', row.id)
        return respond({ error: 'Could not mark the source alert as blocked; the block was rolled back.' }, 500)
      }
    }

    const firewallSync = await syncFirewall(firewallUrl, firewallToken, { action: 'block', ip, reason, expires_at: row.expires_at, request_id: row.id })
    const auditId = `AUD-${crypto.randomUUID()}`
    const { error: auditError } = await db.from('audit_logs').insert({
      id: auditId,
      user_id: authData.user.id,
      action: 'blocked_ip.added',
      target: ip,
      metadata: { reason, firewall_sync: firewallSync, ...(sourceAlert ? { source_alert: sourceAlert.id } : {}) },
    })
    if (auditError) {
      console.error('Could not write block audit event', auditError)
      await db.from('blocked_ips').update({ is_active: false }).eq('id', row.id)
      if (sourceAlert) await db.from('alerts').update({ status: sourceAlert.status }).eq('id', sourceAlert.id)
      if (firewallSync === 'synced') await syncFirewall(firewallUrl, firewallToken, { action: 'unblock', ip, request_id: row.id })
      return respond({ error: 'Block was rolled back because its audit event could not be recorded.' }, 500)
    }
    return respond({ ok: true, block: data, firewall_sync: firewallSync, audit_id: auditId }, 201)
  } catch (error) {
    console.error('block-ip', error)
    return respond({ error: 'Unexpected block action error.' }, 500)
  }
})
