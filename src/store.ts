import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'
import { supabase } from './lib/supabase'
import { seedAlerts, seedAuditLogs, seedBlockedIPs, seedFirewallRules, seedIncidents, seedNotifications, seedPlaybooks, seedSensors } from './data'
import type { Alert, AlertStatus, AppNotification, AppUser, AuditLog, BlockedIP, FirewallRule, Incident, IncidentStatus, Playbook, Sensor } from './types'

interface AppState {
  user: AppUser | null
  alerts: Alert[]
  blockedIPs: BlockedIP[]
  firewallRules: FirewallRule[]
  incidents: Incident[]
  sensors: Sensor[]
  playbooks: Playbook[]
  auditLogs: AuditLog[]
  notifications: AppNotification[]
  lightMode: boolean
  setUser: (user: AppUser | null) => void
  hydrateData: (data: Partial<Pick<AppState, 'alerts' | 'blockedIPs' | 'firewallRules' | 'incidents' | 'sensors' | 'playbooks' | 'auditLogs' | 'notifications'>>) => void
  addAlert: (alert: Alert, fromRealtime?: boolean) => void
  updateAlert: (id: string, changes: Partial<Alert>) => void
  updateManyAlerts: (ids: string[], status: AlertStatus) => void
  addBlockedIP: (record: BlockedIP) => void
  unblockIP: (id: string) => void
  addFirewallRule: (rule: FirewallRule) => void
  updateFirewallRule: (id: string, changes: Partial<FirewallRule>) => void
  removeFirewallRule: (id: string) => void
  toggleFirewallRule: (id: string) => void
  toggleAllFirewall: (enabled: boolean) => void
  addIncident: (incident: Incident) => void
  moveIncident: (id: string, status: IncidentStatus) => void
  addIncidentNote: (id: string, note: string) => void
  togglePlaybook: (id: string) => Promise<void>
  addPlaybook: (playbook: Playbook) => Promise<void>
  updateSensor: (id: string, patch: Partial<Sensor>) => void
  markNotificationsRead: () => void
  pushNotification: (item: AppNotification, fromRealtime?: boolean) => void
  addAuditLog: (item: AuditLog) => void
  updateProfile: (patch: Partial<AppUser>) => void
  toggleTheme: () => void
  resetDemo: () => void
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
function fireDbQuery(query: unknown) {
  if (!query || typeof (query as PromiseLike<{ error?: unknown }>).then !== 'function') return
  void Promise.resolve(query as PromiseLike<{ error?: unknown }>).then(({ error }) => { if (error) console.warn('NetDefender data sync failed:', error) }).catch((error) => console.warn('NetDefender data sync failed:', error))
}
function dbInsert(table: string, payload: Record<string, unknown>) {
  if (supabase) fireDbQuery((supabase as any).from(table).insert(payload))
}
function dbUpdate(table: string, matchField: string, matchValue: unknown, payload: Record<string, unknown>) {
  if (supabase) fireDbQuery((supabase as any).from(table).update(payload).eq(matchField, matchValue))
}
function dbUpdateMany(table: string, matchField: string, values: string[], payload: Record<string, unknown>) {
  if (supabase && values.length) fireDbQuery((supabase as any).from(table).update(payload).in(matchField, values))
}
function dbDelete(table: string, matchField: string, matchValue: unknown) {
  if (supabase) fireDbQuery((supabase as any).from(table).delete().eq(matchField, matchValue))
}

const freshState = () => ({
  alerts: seedAlerts,
  blockedIPs: seedBlockedIPs,
  firewallRules: seedFirewallRules,
  incidents: seedIncidents,
  sensors: seedSensors,
  playbooks: seedPlaybooks,
  auditLogs: seedAuditLogs,
  notifications: seedNotifications,
})

export const useAppStore = create<AppState>()(persist((set, get) => ({
  user: null,
  ...freshState(),
  lightMode: false,
  setUser: (user) => set({ user }),
  hydrateData: (data) => set((state) => ({ ...Object.fromEntries(Object.entries(data).filter(([, value]) => Array.isArray(value))), user: state.user }) as Partial<AppState>),
  addAlert: (alert, fromRealtime = false) => {
    set((state) => state.alerts.some((item) => item.id === alert.id) ? state : ({ alerts: [alert, ...state.alerts].slice(0, 300) }))
    if (!fromRealtime) {
      const payload = { id: alert.id, timestamp: alert.timestamp, severity: alert.severity, source_ip: alert.sourceIp, source_country: alert.sourceCountry, source_lat: alert.sourceLat, source_lng: alert.sourceLng, destination_ip: alert.destinationIp, protocol: alert.protocol, attack_type: alert.attackType, signature: alert.signature, status: alert.status, raw_log: alert.rawLog }
      if (supabase) {
        void Promise.resolve(supabase.from('alerts').insert(payload).select('id').single()).then(async ({ error }) => {
          if (error) { console.warn('NetDefender alert sync failed:', error); return }
          const result = await supabase!.functions.invoke('evaluate-playbooks', { body: { alert_id: alert.id } })
          if (result.error) console.warn('NetDefender playbook evaluation failed:', result.error)
          else if ((result.data as { ok?: boolean; error?: string } | null)?.ok === false) console.warn('NetDefender playbook evaluation failed:', (result.data as { error?: string } | null)?.error)
        }).catch((error: unknown) => console.warn('NetDefender alert sync failed:', error))
      } else {
        dbInsert('alerts', payload)
        if (alert.severity === 'critical') get().pushNotification({ id: `NTF-${Date.now()}`, userId: 'all', title: 'Critical alert detected', message: `${alert.attackType} from ${alert.sourceIp}`, type: 'critical', read: false, createdAt: new Date().toISOString() })
      }
    }
  },
  updateAlert: (id, changes) => {
    set((state) => ({ alerts: state.alerts.map((a) => a.id === id ? { ...a, ...changes } : a) }))
    const dbChanges: Record<string, unknown> = {}
    if (changes.status) dbChanges.status = changes.status
    if (changes.severity) dbChanges.severity = changes.severity
    if (changes.signature) dbChanges.signature = changes.signature
    if (Object.keys(dbChanges).length) dbUpdate('alerts', 'id', id, dbChanges)
  },
  updateManyAlerts: (ids, status) => { set((state) => ({ alerts: state.alerts.map((a) => ids.includes(a.id) ? { ...a, status } : a) })); dbUpdateMany('alerts', 'id', ids, { status }) },
  addBlockedIP: (record) => {
    set((state) => ({ blockedIPs: [record, ...state.blockedIPs] }))
    if (supabase) fireDbQuery(supabase.functions.invoke('block-ip', { body: { ip: record.ip, reason: record.reason, expires_at: record.expiresAt } }))
    else dbInsert('blocked_ips', { id: record.id, ip: record.ip, reason: record.reason, blocked_by: record.blockedBy, blocked_at: record.blockedAt, expires_at: record.expiresAt, is_active: record.isActive })
  },
  unblockIP: (id) => {
    const record = get().blockedIPs.find((item) => item.id === id)
    set((state) => ({ blockedIPs: state.blockedIPs.map((b) => b.id === id ? { ...b, isActive: false } : b) }))
    if (supabase && record) fireDbQuery(supabase.functions.invoke('block-ip', { body: { action: 'unblock', id, ip: record.ip } }))
    else dbUpdate('blocked_ips', 'id', id, { is_active: false })
  },
  addFirewallRule: (rule) => {
    set((state) => ({ firewallRules: [rule, ...state.firewallRules] }))
    dbInsert('firewall_rules', { id: rule.id, name: rule.name, action: rule.action, protocol: rule.protocol, source: rule.source, destination: rule.destination, port: rule.port, enabled: rule.enabled, created_by: rule.createdBy, created_at: rule.createdAt })
  },
  updateFirewallRule: (id, changes) => {
    set((state) => ({ firewallRules: state.firewallRules.map((rule) => rule.id === id ? { ...rule, ...changes } : rule) }))
    const dbChanges: Record<string, unknown> = { ...changes }
    if ('createdBy' in changes) { dbChanges.created_by = changes.createdBy; delete dbChanges.createdBy }
    if ('createdAt' in changes) { dbChanges.created_at = changes.createdAt; delete dbChanges.createdAt }
    dbUpdate('firewall_rules', 'id', id, dbChanges)
  },
  removeFirewallRule: (id) => { set((state) => ({ firewallRules: state.firewallRules.filter((rule) => rule.id !== id) })); dbDelete('firewall_rules', 'id', id) },
  toggleFirewallRule: (id) => {
    const current = get().firewallRules.find((rule) => rule.id === id)
    if (current) dbUpdate('firewall_rules', 'id', id, { enabled: !current.enabled })
    set((state) => ({ firewallRules: state.firewallRules.map((r) => r.id === id ? { ...r, enabled: !r.enabled } : r) }))
  },
  toggleAllFirewall: (enabled) => { set((state) => ({ firewallRules: state.firewallRules.map((r) => ({ ...r, enabled })) })); if (supabase) fireDbQuery((supabase as any).from('firewall_rules').update({ enabled }).neq('id', '')) },
  addIncident: (incident) => {
    set((state) => ({ incidents: [incident, ...state.incidents] }))
    dbInsert('incidents', { id: incident.id, title: incident.title, description: incident.description, severity: incident.severity, status: incident.status, assigned_to: incident.assignedTo, created_at: incident.createdAt, resolved_at: incident.resolvedAt || null, notes: incident.notes })
  },
  moveIncident: (id, status) => {
    const resolvedAt = status === 'resolved' ? new Date().toISOString() : null
    set((state) => ({ incidents: state.incidents.map((i) => i.id === id ? { ...i, status, resolvedAt } : i) }))
    dbUpdate('incidents', 'id', id, { status, resolved_at: resolvedAt })
  },
  addIncidentNote: (id, note) => {
    const incident = get().incidents.find((item) => item.id === id)
    set((state) => ({ incidents: state.incidents.map((i) => i.id === id ? { ...i, notes: [...i.notes, note] } : i) }))
    if (incident) dbUpdate('incidents', 'id', id, { notes: [...incident.notes, note] })
  },
  togglePlaybook: async (id) => {
    const current = get().playbooks.find((item) => item.id === id)
    if (!current) return
    const enabled = !current.enabled
    if (supabase) {
      const { error } = await supabase.from('playbooks').update({ enabled }).eq('id', id)
      if (error) throw error
    }
    set((state) => ({ playbooks: state.playbooks.map((p) => p.id === id ? { ...p, enabled } : p) }))
  },
  addPlaybook: async (playbook) => {
    if (supabase) {
      const { error } = await supabase.from('playbooks').insert({ id: playbook.id, name: playbook.name, trigger_condition: playbook.triggerCondition, condition_json: playbook.condition, actions_json: playbook.actions, enabled: playbook.enabled, created_at: playbook.createdAt })
      if (error) throw error
    }
    set((state) => state.playbooks.some((item) => item.id === playbook.id) ? state : ({ playbooks: [playbook, ...state.playbooks] }))
  },
  updateSensor: (id, patch) => {
    set((state) => ({ sensors: state.sensors.map((sensor) => sensor.id === id ? { ...sensor, ...patch } : sensor) }))
    const dbChanges: Record<string, unknown> = { ...patch }
    if ('lastHeartbeat' in patch) { dbChanges.last_heartbeat = patch.lastHeartbeat; delete dbChanges.lastHeartbeat }
    dbUpdate('sensors', 'id', id, dbChanges)
  },
  markNotificationsRead: () => { set((state) => ({ notifications: state.notifications.map((n) => ({ ...n, read: true })) })); const id = get().user?.id; if (id && uuidPattern.test(id)) dbUpdateMany('notifications', 'user_id', [id], { read: true }) },
  pushNotification: (item, fromRealtime = false) => {
    set((state) => state.notifications.some((notification) => notification.id === item.id) ? state : ({ notifications: [item, ...state.notifications] }))
    if (!fromRealtime && item.userId !== 'all' && uuidPattern.test(item.userId)) dbInsert('notifications', { id: item.id, user_id: item.userId, title: item.title, message: item.message, type: item.type, read: item.read, created_at: item.createdAt })
  },
  addAuditLog: (item) => {
    set((state) => ({ auditLogs: [item, ...state.auditLogs] }))
    if (uuidPattern.test(item.userId)) dbInsert('audit_logs', { id: item.id, user_id: item.userId, action: item.action, target: item.target, metadata: item.metadata, created_at: item.createdAt })
  },
  updateProfile: (patch) => {
    set((state) => ({ user: state.user ? { ...state.user, ...patch } : null }))
    const id = get().user?.id
    if (id && uuidPattern.test(id)) dbUpdate('profiles', 'id', id, { ...(patch.fullName ? { full_name: patch.fullName } : {}), ...(patch.email ? { email: patch.email } : {}) })
  },
  toggleTheme: () => set((state) => ({ lightMode: !state.lightMode })),
  resetDemo: () => set({ ...freshState() }),
}), {
  name: 'netdefender-state-v1',
  storage: createJSONStorage(() => localStorage),
  partialize: (state) => ({
    user: state.user,
    alerts: state.alerts,
    blockedIPs: state.blockedIPs,
    firewallRules: state.firewallRules,
    incidents: state.incidents,
    sensors: state.sensors,
    playbooks: state.playbooks,
    auditLogs: state.auditLogs,
    notifications: state.notifications,
    lightMode: state.lightMode,
  }),
}))
