import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.4'

const origins = [
  { ip: '185.220.101.45', country: 'Russia', lat: 55.75, lng: 37.62 },
  { ip: '103.74.118.23', country: 'China', lat: 31.23, lng: 121.47 },
  { ip: '198.98.57.12', country: 'United States', lat: 39.74, lng: -104.99 },
  { ip: '177.54.148.77', country: 'Brazil', lat: -23.55, lng: -46.63 },
  { ip: '45.155.205.233', country: 'India', lat: 19.08, lng: 72.88 },
  { ip: '91.240.118.172', country: 'Iran', lat: 35.69, lng: 51.39 },
  { ip: '175.45.176.14', country: 'North Korea', lat: 39.02, lng: 125.75 },
]
const attacks = [
  { type: 'Port Scan', signature: 'ET SCAN Potential service discovery scan', protocol: 'TCP', severity: 'low' },
  { type: 'SSH Brute Force', signature: 'ET POLICY SSH brute force attempt', protocol: 'TCP', severity: 'high' },
  { type: 'SQL Injection', signature: 'ET WEB_SERVER SQL injection attempt', protocol: 'HTTPS', severity: 'critical' },
  { type: 'DDoS', signature: 'ET DOS Possible UDP amplification attack', protocol: 'UDP', severity: 'high' },
  { type: 'Malware C2', signature: 'ET TROJAN C2 beacon detected', protocol: 'TCP', severity: 'medium' },
  { type: 'XSS', signature: 'ET WEB_CLIENT Cross-site scripting attempt', protocol: 'HTTPS', severity: 'medium' },
  { type: 'Ransomware', signature: 'ET MALWARE Ransomware payload delivery', protocol: 'TCP', severity: 'critical' },
  { type: 'Zero-Day Exploit', signature: 'ET EXPLOIT Suspicious memory corruption pattern', protocol: 'TCP', severity: 'critical' },
]
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

Deno.serve(async (request) => {
  if (request.method !== 'POST') return response({ error: 'POST required' }, 405)
  const secret = Deno.env.get('SIMULATOR_CRON_SECRET')
  if (!secret || request.headers.get('x-cron-secret') !== secret) return response({ error: 'Unauthorized scheduler request' }, 401)
  try {
    const db = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false } })
    const source = origins[Math.floor(Math.random() * origins.length)]
    const attack = attacks[Math.floor(Math.random() * attacks.length)]
    const destination = `10.24.${Math.floor(Math.random() * 5) + 1}.${Math.floor(Math.random() * 220) + 20}`
    const timestamp = new Date().toISOString()
    const record = {
      id: `ALT-${crypto.randomUUID()}`,
      timestamp,
      severity: attack.severity,
      source_ip: source.ip,
      source_country: source.country,
      source_lat: source.lat,
      source_lng: source.lng,
      destination_ip: destination,
      protocol: attack.protocol,
      attack_type: attack.type,
      signature: attack.signature,
      status: 'new',
      raw_log: `[${timestamp}] [**] ${attack.signature} [**]\n[src=${source.ip} dst=${destination} proto=${attack.protocol}]\n[Classification: Attempted ${attack.type}]`,
    }
    const { data, error } = await db.from('alerts').insert(record).select('id, severity, source_ip, attack_type').single()
    if (error) throw error
    let automation: unknown = null
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    try {
      const evaluation = await fetch(`${supabaseUrl}/functions/v1/evaluate-playbooks`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${serviceKey}`, apikey: serviceKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: record.id }),
      })
      automation = await evaluation.json().catch(() => null)
      if (!evaluation.ok) console.error('evaluate-playbooks returned', evaluation.status, automation)
    } catch (error) {
      console.error('evaluate-playbooks dispatch failed', error)
    }
    return response({ ok: true, alert: data, automation }, 201)
  } catch (error) {
    console.error('simulate-traffic', error)
    return response({ error: 'Simulation insert failed' }, 500)
  }
})
