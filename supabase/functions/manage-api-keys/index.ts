import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.4'

const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }
const respond = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
async function sha256(value: string) { const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)); return Array.from(new Uint8Array(hash)).map((byte) => byte.toString(16).padStart(2, '0')).join('') }

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (request.method !== 'POST') return respond({ error: 'POST required' }, 405)
  try {
    const url = Deno.env.get('SUPABASE_URL')!
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!
    const token = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '')
    if (!token) return respond({ error: 'Authentication required' }, 401)
    const userClient = createClient(url, anonKey, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false } })
    const { data: authData, error: authError } = await userClient.auth.getUser(token)
    if (authError || !authData.user) return respond({ error: 'Invalid session' }, 401)
    const service = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false } })
    const { data: profile } = await service.from('profiles').select('role').eq('id', authData.user.id).maybeSingle()
    if (profile?.role !== 'admin') return respond({ error: 'Admin role required' }, 403)
    const body = await request.json()
    const action = String(body.action || '')
    if (action === 'list') {
      const { data, error } = await service.from('api_keys').select('id,name,key_prefix,created_at,last_used_at,revoked_at').order('created_at', { ascending: false })
      if (error) throw error
      return respond({ keys: data })
    }
    if (action === 'create') {
      const name = String(body.name || 'SOC API key').trim().slice(0, 80)
      if (name.length < 3) return respond({ error: 'Key name must be at least 3 characters.' }, 400)
      const bytes = crypto.getRandomValues(new Uint8Array(32))
      const secret = `nd_live_${Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('')}`
      const keyHash = await sha256(secret)
      const { data, error } = await service.from('api_keys').insert({ name, key_hash: keyHash, key_prefix: secret.slice(0, 15), created_by: authData.user.id }).select('id,name,key_prefix,created_at,last_used_at,revoked_at').single()
      if (error) throw error
      return respond({ key: data, secret }, 201)
    }
    if (action === 'revoke') {
      const id = String(body.id || '')
      if (!id) return respond({ error: 'Key id is required.' }, 400)
      const { data, error } = await service.from('api_keys').update({ revoked_at: new Date().toISOString() }).eq('id', id).is('revoked_at', null).select('id').single()
      if (error || !data) return respond({ error: 'Key not found or already revoked.' }, 404)
      await service.from('audit_logs').insert({ id: `AUD-${crypto.randomUUID()}`, user_id: authData.user.id, action: 'api_key.revoked', target: id, metadata: {} })
      return respond({ ok: true })
    }
    return respond({ error: 'Unsupported key action.' }, 400)
  } catch (error) {
    console.error('manage-api-keys', error)
    return respond({ error: 'API key operation failed.' }, 500)
  }
})
