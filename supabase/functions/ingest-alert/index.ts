import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.4'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-api-key',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/
const severities = new Set(['low', 'medium', 'high', 'critical'])

async function sha256(value: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (request.method !== 'POST') return response({ error: 'Method not allowed' }, 405)
  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const db = createClient(supabaseUrl, serviceKey, { auth: { persistSession: false } })
    const apiKey = request.headers.get('x-api-key') || request.headers.get('authorization')?.replace(/^Bearer\s+/i, '')
    if (!apiKey || apiKey.length < 28) return response({ error: 'A valid NetDefender API key is required.' }, 401)
    const keyHash = await sha256(apiKey)
    const { data: keyRecord, error: keyError } = await db.from('api_keys').select('id, key_prefix').eq('key_hash', keyHash).is('revoked_at', null).maybeSingle()
    if (keyError || !keyRecord) return response({ error: 'Invalid or revoked API key.' }, 401)

    const { data: allowed, error: rateError } = await db.rpc('consume_api_key_rate_limit', { p_key_id: keyRecord.id, p_limit: 120, p_window_seconds: 60 })
    if (rateError) { console.error('Rate-limit check unavailable', rateError); return response({ error: 'Rate-limit service unavailable. Retry shortly.' }, 503) }
    if (!allowed) return response({ error: 'Rate limit exceeded. Try again in one minute.' }, 429)
    await db.from('api_keys').update({ last_used_at: new Date().toISOString() }).eq('id', keyRecord.id)

    const input = await request.json()
    const sourceIp = String(input.source_ip || '').trim()
    const severity = String(input.severity || 'medium').toLowerCase()
    const attackType = String(input.attack_type || '').trim()
    if (!ipv4.test(sourceIp)) return response({ error: 'source_ip must be a valid IPv4 address.' }, 400)
    if (!severities.has(severity)) return response({ error: 'severity must be low, medium, high, or critical.' }, 400)
    if (attackType.length < 2 || attackType.length > 120) return response({ error: 'attack_type is required and must be at most 120 characters.' }, 400)
    const timestamp = input.timestamp && !Number.isNaN(Date.parse(input.timestamp)) ? new Date(input.timestamp).toISOString() : new Date().toISOString()
    const record = {
      id: `ALT-${crypto.randomUUID()}`,
      timestamp,
      severity,
      source_ip: sourceIp,
      source_country: String(input.source_country || 'Unknown').slice(0, 80),
      source_lat: Number.isFinite(Number(input.source_lat)) ? Number(input.source_lat) : null,
      source_lng: Number.isFinite(Number(input.source_lng)) ? Number(input.source_lng) : null,
      destination_ip: String(input.destination_ip || '').slice(0, 64),
      protocol: String(input.protocol || 'TCP').toUpperCase().slice(0, 16),
      attack_type: attackType,
      signature: String(input.signature || 'External sensor event').slice(0, 240),
      status: 'new',
      raw_log: String(input.raw_log || '').slice(0, 20_000),
    }
    const { data, error } = await db.from('alerts').insert(record).select('*').single()
    if (error) return response({ error: 'Alert could not be stored.', detail: error.message }, 500)
    let automation: unknown = null
    try {
      const evaluation = await fetch(`${supabaseUrl}/functions/v1/evaluate-playbooks`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${serviceKey}`, apikey: serviceKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: record.id }),
      })
      automation = await evaluation.json().catch(() => null)
      if (!evaluation.ok) console.error('Playbook evaluation returned', evaluation.status, automation)
    } catch (error) {
      console.error('Playbook evaluation dispatch failed', error)
    }
    return response({ ok: true, alert: data, automation }, 201)
  } catch (error) {
    console.error('ingest-alert', error)
    return response({ error: 'Invalid request payload.' }, 400)
  }
})
