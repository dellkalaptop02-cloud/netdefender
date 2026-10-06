import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.4'

const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
Deno.serve(async (request) => {
  if (request.method !== 'POST') return response({ error: 'POST required' }, 405)
  const secret = Deno.env.get('EXPIRE_BLOCKS_CRON_SECRET')
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const supplied = request.headers.get('x-cron-secret') || request.headers.get('authorization')?.replace(/^Bearer\s+/i, '')
  if (!secret || supplied !== secret && supplied !== serviceKey) return response({ error: 'Unauthorized scheduler request' }, 401)
  try {
    const db = createClient(Deno.env.get('SUPABASE_URL')!, serviceKey, { auth: { persistSession: false } })
    const now = new Date().toISOString()
    const rateLimitCutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
    const { data: prunedBuckets, error: pruneError } = await db.from('api_key_rate_limits').delete().lt('window_start', rateLimitCutoff).select('key_id')
    if (pruneError) throw pruneError
    const { data: expired, error: selectError } = await db.from('blocked_ips').select('id,ip,reason').eq('is_active', true).lte('expires_at', now)
    if (selectError) throw selectError
    if (!expired?.length) return response({ ok: true, expired: 0, rate_limit_buckets_pruned: prunedBuckets?.length || 0 })
    const ids = expired.map((item) => item.id)
    const { error } = await db.from('blocked_ips').update({ is_active: false }).in('id', ids)
    if (error) throw error
    const webhookUrl = Deno.env.get('FIREWALL_WEBHOOK_URL')
    const webhookToken = Deno.env.get('FIREWALL_WEBHOOK_TOKEN')
    const webhookResults = await Promise.allSettled(expired.map((item) => webhookUrl ? fetch(webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(webhookToken ? { Authorization: `Bearer ${webhookToken}` } : {}) }, body: JSON.stringify({ action: 'unblock', ip: item.ip, reason: 'Block duration expired', request_id: item.id }) }) : Promise.resolve()))
    const auditRows = expired.map((item) => ({ id: `AUD-${crypto.randomUUID()}`, user_id: null, action: 'blocked_ip.expired', target: item.ip, metadata: { block_id: item.id, reason: item.reason } }))
    await db.from('audit_logs').insert(auditRows)
    return response({ ok: true, expired: expired.length, rate_limit_buckets_pruned: prunedBuckets?.length || 0, firewall_webhook_configured: Boolean(webhookUrl), webhook_failures: webhookResults.filter((result) => result.status === 'rejected').length })
  } catch (error) {
    console.error('expire-blocks', error)
    return response({ error: 'Could not expire block entries' }, 500)
  }
})
