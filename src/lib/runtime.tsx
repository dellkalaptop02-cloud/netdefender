import { useEffect, useState } from 'react'
import { create } from 'zustand'
import { supabase } from './supabase'
import { useAppStore } from '../store'
import { seedSensors } from '../data'
import type { Alert, AppNotification, AppUser, BlockedIP, FirewallRule, Incident, Playbook, PlaybookCondition, PlaybookField, PlaybookOperator, Role, Sensor, Severity } from '../types'

type LiveState = { connected: boolean; hydrating: boolean; lastHeartbeat: string; liveAlertId: string | null; setConnected: (value: boolean) => void; setHydrating: (value: boolean) => void; markLiveAlert: (id: string) => void; beat: () => void }
export const useLiveState = create<LiveState>((set) => ({ connected: false, hydrating: Boolean(supabase), lastHeartbeat: new Date().toISOString(), liveAlertId: null, setConnected: (connected) => set({ connected }), setHydrating: (hydrating) => set({ hydrating }), markLiveAlert: (id) => { set({ liveAlertId: id }); window.setTimeout(() => set((state) => state.liveAlertId === id ? { liveAlertId: null } : {}), 950) }, beat: () => set({ lastHeartbeat: new Date().toISOString() }) }))

const defaultDemoUser: AppUser = { id: 'demo-admin-001', email: 'admin@netdefender.io', fullName: 'Alex Morgan', role: 'admin' }
const demoOrigins = [
  { ip: '185.220.101.45', country: 'Russia', lat: 55.75, lng: 37.62 }, { ip: '103.74.118.23', country: 'China', lat: 31.23, lng: 121.47 },
  { ip: '198.98.57.12', country: 'United States', lat: 39.74, lng: -104.99 }, { ip: '177.54.148.77', country: 'Brazil', lat: -23.55, lng: -46.63 },
  { ip: '45.155.205.233', country: 'India', lat: 19.08, lng: 72.88 }, { ip: '91.240.118.172', country: 'Iran', lat: 35.69, lng: 51.39 },
]
const demoAttacks = [
  { type: 'Port Scan', signature: 'ET SCAN Potential service discovery scan', severity: 'low' as Severity, protocol: 'TCP' },
  { type: 'SSH Brute Force', signature: 'ET POLICY SSH brute force attempt', severity: 'high' as Severity, protocol: 'TCP' },
  { type: 'SQL Injection', signature: 'ET WEB_SERVER SQL injection attempt', severity: 'critical' as Severity, protocol: 'HTTPS' },
  { type: 'DDoS', signature: 'ET DOS Possible UDP amplification attack', severity: 'high' as Severity, protocol: 'UDP' },
  { type: 'Malware C2', signature: 'ET TROJAN C2 beacon detected', severity: 'medium' as Severity, protocol: 'TCP' },
  { type: 'XSS', signature: 'ET WEB_CLIENT Cross-site scripting attempt', severity: 'medium' as Severity, protocol: 'HTTPS' },
]

function mapCoordinate(value: unknown, min: number, max: number): number | null {
  if (value === null || value === undefined || value === '') return null
  const number = Number(value)
  return Number.isFinite(number) && number >= min && number <= max ? number : null
}

function mapAlert(row: Record<string, unknown>): Alert {
  return {
    id: String(row.id || `ALT-${Date.now()}`), timestamp: String(row.timestamp || row.created_at || new Date().toISOString()), severity: String(row.severity || 'medium').toLowerCase() as Severity,
    sourceIp: String(row.source_ip || ''), sourceCountry: String(row.source_country || 'Unknown'), sourceLat: mapCoordinate(row.source_lat, -90, 90), sourceLng: mapCoordinate(row.source_lng, -180, 180),
    destinationIp: String(row.destination_ip || ''), protocol: String(row.protocol || 'TCP'), attackType: String(row.attack_type || 'Unknown'), signature: String(row.signature || ''),
    status: String(row.status || 'new') as Alert['status'], rawLog: String(row.raw_log || ''),
  }
}
function mapBlocked(row: Record<string, unknown>): BlockedIP {
  return { id: String(row.id), ip: String(row.ip || ''), reason: String(row.reason || ''), blockedBy: String(row.blocked_by || 'SOC team'), blockedAt: String(row.blocked_at || row.created_at || new Date().toISOString()), expiresAt: row.expires_at ? String(row.expires_at) : null, isActive: Boolean(row.is_active) }
}
function mapSensor(row: Record<string, unknown>): Sensor {
  const seed = seedSensors[0]
  const type = String(row.type || 'Suricata') as Sensor['type']
  const status = String(row.status || 'online') as Sensor['status']
  return { id: String(row.id), name: String(row.name || seed.name), type, ip: String(row.ip || '0.0.0.0'), status, cpu: Number(row.cpu || 0), memory: Number(row.memory || 0), uptime: String(row.uptime || '—'), lastHeartbeat: String(row.last_heartbeat || new Date().toISOString()) }
}
function mapRule(row: Record<string, unknown>): FirewallRule {
  return { id: String(row.id), name: String(row.name), action: String(row.action) as FirewallRule['action'], protocol: String(row.protocol || 'ANY'), source: String(row.source || 'ANY'), destination: String(row.destination || 'ANY'), port: String(row.port || 'ANY'), enabled: Boolean(row.enabled), createdBy: String(row.created_by || 'SOC team'), createdAt: String(row.created_at || new Date().toISOString()) }
}
function mapIncident(row: Record<string, unknown>): Incident {
  return { id: String(row.id), title: String(row.title), description: String(row.description || ''), severity: String(row.severity || 'medium') as Severity, status: String(row.status || 'new') as Incident['status'], assignedTo: String(row.assigned_to || 'Unassigned'), createdAt: String(row.created_at || new Date().toISOString()), resolvedAt: row.resolved_at ? String(row.resolved_at) : null, notes: Array.isArray(row.notes) ? row.notes.map(String) : [] }
}
const playbookFields = new Set<PlaybookField>(['severity', 'attack_type', 'source_country', 'protocol'])
const playbookOperators = new Set<PlaybookOperator>(['equals', 'contains', 'greater_than'])
function mapPlaybookCondition(value: unknown, triggerCondition: string): PlaybookCondition {
  if (value && typeof value === 'object') {
    const candidate = value as Record<string, unknown>
    const conditionValue = candidate.value === undefined || candidate.value === null ? '' : String(candidate.value).trim()
    if (playbookFields.has(candidate.field as PlaybookField) && playbookOperators.has(candidate.operator as PlaybookOperator) && conditionValue && (candidate.operator !== 'greater_than' || candidate.field === 'severity')) {
      return { field: candidate.field as PlaybookField, operator: candidate.operator as PlaybookOperator, value: conditionValue }
    }
  }
  const match = /^(severity|attack_type|source_country|protocol)\s*(=|contains|>)\s*(.+)$/i.exec(triggerCondition.trim())
  if (match) return { field: match[1].toLowerCase() as PlaybookField, operator: match[2] === '>' ? 'greater_than' : match[2] === '=' ? 'equals' : 'contains', value: match[3].trim() }
  return { field: 'severity', operator: 'equals', value: 'critical' }
}
function mapPlaybook(row: Record<string, unknown>): Playbook {
  const triggerCondition = String(row.trigger_condition || '')
  const actionList = Array.isArray(row.actions_json) ? row.actions_json : []
  return { id: String(row.id), name: String(row.name), triggerCondition, condition: mapPlaybookCondition(row.condition_json, triggerCondition), actions: actionList.map(String), enabled: Boolean(row.enabled), createdAt: String(row.created_at || new Date().toISOString()) }
}

async function appUserFromSession(sessionUser: { id: string; email?: string; user_metadata?: Record<string, unknown> } | null): Promise<AppUser | null> {
  if (!sessionUser) return null
  let fullName = String(sessionUser.user_metadata?.full_name || sessionUser.email?.split('@')[0] || 'SOC operator')
  let role: Role = 'viewer'
  if (supabase) {
    const { data } = await supabase.from('profiles').select('full_name, role').eq('id', sessionUser.id).maybeSingle()
    if (data) { const row = data as { full_name?: string; role?: Role }; fullName = row.full_name || fullName; role = row.role || 'viewer' }
  }
  return { id: sessionUser.id, email: sessionUser.email || '', fullName, role }
}

export function useApplicationRuntime() {
  const [authReady, setAuthReady] = useState(false)
  const setUser = useAppStore((state) => state.setUser)
  const sessionUserId = useAppStore((state) => state.user?.id || null)
  const hydrateData = useAppStore((state) => state.hydrateData)
  const addAlert = useAppStore((state) => state.addAlert)
  const setConnected = useLiveState((state) => state.setConnected)
  const setHydrating = useLiveState((state) => state.setHydrating)
  const beat = useLiveState((state) => state.beat)
  const markLiveAlert = useLiveState((state) => state.markLiveAlert)

  useEffect(() => {
    if (!supabase) {
      const hasSavedWorkspace = Boolean(localStorage.getItem('netdefender-state-v1'))
      if (!hasSavedWorkspace) setUser(defaultDemoUser)
      setHydrating(false)
      setAuthReady(true)
      return
    }
    let active = true
    supabase.auth.getSession().then(async ({ data }) => {
      if (!active) return
      setUser(await appUserFromSession(data.session?.user || null))
      setAuthReady(true)
    }).catch(() => { if (active) { setUser(null); setAuthReady(true) } })
    const { data: authListener } = supabase.auth.onAuthStateChange((_event, session) => {
      if (!active) return
      void appUserFromSession(session?.user || null).then((user) => { if (active) { setUser(user); setAuthReady(true) } })
    })
    return () => { active = false; authListener.subscription.unsubscribe() }
  }, [setUser, setHydrating])

  useEffect(() => {
    if (!authReady) return
    if (!supabase) {
      setHydrating(false)
      setConnected(true); beat()
      const timer = window.setInterval(() => {
        const source = demoOrigins[Math.floor(Math.random() * demoOrigins.length)]
        const attack = demoAttacks[Math.floor(Math.random() * demoAttacks.length)]
        const timestamp = new Date().toISOString()
        const destination = `10.24.${Math.ceil(Math.random() * 5)}.${Math.ceil(Math.random() * 220 + 20)}`
        const liveAlert = { id: `ALT-${Date.now().toString().slice(-7)}`, timestamp, severity: attack.severity, sourceIp: source.ip, sourceCountry: source.country, sourceLat: source.lat, sourceLng: source.lng, destinationIp: destination, protocol: attack.protocol, attackType: attack.type, signature: attack.signature, status: 'new' as const, rawLog: `[${timestamp}] [**] ${attack.signature} [**]\n[src=${source.ip} dst=${destination} proto=${attack.protocol}]\n[Classification: Attempted ${attack.type}]` }
        markLiveAlert(liveAlert.id)
        addAlert(liveAlert)
        beat()
      }, 15_000)
      return () => window.clearInterval(timer)
    }
    if (!sessionUserId) { setConnected(false); setHydrating(false); return }

    let active = true
    setHydrating(true)
    const currentUser = useAppStore.getState().user
    const channel = supabase.channel('netdefender-live')
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'alerts' }, (payload) => {
        const alert = mapAlert(payload.new as Record<string, unknown>)
        if (!useAppStore.getState().alerts.some((item) => item.id === alert.id)) markLiveAlert(alert.id)
        addAlert(alert, true)
        beat()
      })
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'alerts' }, (payload) => {
        const updated = mapAlert(payload.new as Record<string, unknown>)
        useAppStore.setState((state) => ({ alerts: state.alerts.map((item) => item.id === updated.id ? updated : item) })); beat()
      })
      .on('postgres_changes', { event: '*', schema: 'public', table: 'blocked_ips' }, async () => {
        const { data } = await supabase!.from('blocked_ips').select('*').order('blocked_at', { ascending: false })
        if (data) hydrateData({ blockedIPs: (data as Record<string, unknown>[]).map(mapBlocked) }); beat()
      })
      .on('postgres_changes', { event: '*', schema: 'public', table: 'sensors' }, async () => {
        const { data } = await supabase!.from('sensors').select('*')
        if (data) hydrateData({ sensors: (data as Record<string, unknown>[]).map(mapSensor) }); beat()
      })
      .on('postgres_changes', { event: '*', schema: 'public', table: 'incidents' }, async () => {
        const { data } = await supabase!.from('incidents').select('*').order('created_at', { ascending: false })
        if (data) hydrateData({ incidents: (data as Record<string, unknown>[]).map(mapIncident) }); beat()
      })
    if (currentUser?.id) channel.on('postgres_changes', { event: '*', schema: 'public', table: 'notifications', filter: `user_id=eq.${currentUser.id}` }, (payload) => {
      const row = payload.new as Record<string, unknown>
      const item: AppNotification = { id: String(row.id), userId: String(row.user_id), title: String(row.title), message: String(row.message), type: String(row.type || 'info') as AppNotification['type'], read: Boolean(row.read), createdAt: String(row.created_at) }
      if (payload.eventType === 'INSERT') useAppStore.getState().pushNotification(item, true)
      else useAppStore.setState((state) => ({ notifications: state.notifications.map((notification) => notification.id === item.id ? item : notification) }))
      beat()
    })
    channel.subscribe((status) => setConnected(status === 'SUBSCRIBED'))

    const hydrate = async () => {
      try {
        const [alertRows, blockRows, sensorRows, ruleRows, incidentRows, playbookRows, auditRows, notificationRows] = await Promise.all([
          supabase!.from('alerts').select('*').order('timestamp', { ascending: false }).limit(300),
          supabase!.from('blocked_ips').select('*').order('blocked_at', { ascending: false }),
          supabase!.from('sensors').select('*'),
          supabase!.from('firewall_rules').select('*').order('created_at', { ascending: false }),
          supabase!.from('incidents').select('*').order('created_at', { ascending: false }),
          supabase!.from('playbooks').select('*').order('created_at', { ascending: false }),
          supabase!.from('audit_logs').select('*, profiles(full_name)').order('created_at', { ascending: false }).limit(500),
          supabase!.from('notifications').select('*').order('created_at', { ascending: false }).limit(100),
        ])
        if (!active) return
        const data: Parameters<typeof hydrateData>[0] = {}
        if (alertRows.data) data.alerts = (alertRows.data as Record<string, unknown>[]).map(mapAlert)
        if (blockRows.data) data.blockedIPs = (blockRows.data as Record<string, unknown>[]).map(mapBlocked)
        if (sensorRows.data) data.sensors = (sensorRows.data as Record<string, unknown>[]).map(mapSensor)
        if (ruleRows.data) data.firewallRules = (ruleRows.data as Record<string, unknown>[]).map(mapRule)
        if (incidentRows.data) data.incidents = (incidentRows.data as Record<string, unknown>[]).map(mapIncident)
        if (playbookRows.data) data.playbooks = (playbookRows.data as Record<string, unknown>[]).map(mapPlaybook)
        if (auditRows.data) data.auditLogs = (auditRows.data as Record<string, unknown>[]).map((row) => { const metadata = (row.metadata || {}) as Record<string, unknown>; return { id: String(row.id), userId: String(row.user_id || ''), userName: String((row.profiles as { full_name?: string } | null)?.full_name || metadata.actor || 'SOC operator'), action: String(row.action), target: String(row.target || ''), metadata, createdAt: String(row.created_at) } })
        if (notificationRows.data) data.notifications = (notificationRows.data as Record<string, unknown>[]).map((row): AppNotification => ({ id: String(row.id), userId: String(row.user_id || ''), title: String(row.title), message: String(row.message), type: String(row.type || 'info') as AppNotification['type'], read: Boolean(row.read), createdAt: String(row.created_at) }))
        if (Object.keys(data).length) hydrateData(data)
      } catch (error) {
        console.error('Could not hydrate the NetDefender workspace:', error)
      } finally {
        if (active) setHydrating(false)
      }
    }
    void hydrate()
    return () => { active = false; setHydrating(false); void supabase?.removeChannel(channel); setConnected(false) }
  }, [authReady, sessionUserId, addAlert, beat, hydrateData, setConnected, setHydrating, markLiveAlert])

  return authReady
}
