import { supabase } from './supabase'
import { useAppStore } from '../store'
import type { Alert, AppUser, AuditLog, BlockedIP } from '../types'

function isUnexpiredBlock(entry: BlockedIP, now = Date.now()) {
  return entry.isActive && (!entry.expiresAt || new Date(entry.expiresAt).getTime() > now)
}

export function isIPCurrentlyBlocked(entries: BlockedIP[], ip: string) {
  return entries.some((entry) => entry.ip === ip && isUnexpiredBlock(entry))
}

function mapBlockRow(value: unknown, fallback: BlockedIP): BlockedIP {
  if (!value || typeof value !== 'object') return fallback
  const row = value as Record<string, unknown>
  return {
    id: String(row.id || fallback.id),
    ip: String(row.ip || fallback.ip),
    reason: String(row.reason || fallback.reason),
    blockedBy: String(row.blocked_by || fallback.blockedBy),
    blockedAt: String(row.blocked_at || fallback.blockedAt),
    expiresAt: row.expires_at ? String(row.expires_at) : null,
    isActive: row.is_active === undefined ? fallback.isActive : Boolean(row.is_active),
  }
}

function appendLocalAudit(audit: AuditLog) {
  useAppStore.setState((state) => state.auditLogs.some((item) => item.id === audit.id) ? state : ({ auditLogs: [audit, ...state.auditLogs] }))
}

export async function recordAuditEvent(audit: AuditLog) {
  if (supabase) {
    const { error } = await supabase.from('audit_logs').insert({
      id: audit.id,
      user_id: audit.userId,
      action: audit.action,
      target: audit.target,
      metadata: audit.metadata,
      created_at: audit.createdAt,
    })
    if (error) throw error
  }
  appendLocalAudit(audit)
}

export async function activateFirewallKillSwitch(user: AppUser | null, origin: 'settings' | 'firewall' = 'settings') {
  if (user?.role !== 'admin') throw new Error('Administrator access is required to activate the firewall kill switch.')
  const enabledRuleIds = useAppStore.getState().firewallRules.filter((rule) => rule.enabled).map((rule) => rule.id)

  if (supabase) {
    const { error } = await supabase.from('firewall_rules').update({ enabled: false }).neq('id', '')
    if (error) throw new Error(`Firewall rules could not be disabled: ${error.message}`)
  }

  useAppStore.setState((state) => ({ firewallRules: state.firewallRules.map((rule) => ({ ...rule, enabled: false })) }))

  const audit: AuditLog = {
    id: `AUD-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`,
    userId: user.id,
    userName: user.fullName,
    action: 'firewall.kill_switch',
    target: 'All firewall rules',
    metadata: { disabledRules: enabledRuleIds.length, disabledRuleIds: enabledRuleIds, origin },
    createdAt: new Date().toISOString(),
  }

  try {
    await recordAuditEvent(audit)
    return { disabledRules: enabledRuleIds.length, auditLogged: true as const }
  } catch (error) {
    return { disabledRules: enabledRuleIds.length, auditLogged: false as const, auditError: error instanceof Error ? error.message : 'Audit database write failed.' }
  }
}

export async function createIPBlock({ ip, reason, expiresAt, user, sourceAlert }: {
  ip: string
  reason: string
  expiresAt: string | null
  user: AppUser | null
  sourceAlert?: Alert
}): Promise<{ alreadyBlocked: boolean; record?: BlockedIP }> {
  if (user?.role !== 'admin') throw new Error('Administrator access is required to block an IP address.')
  const store = useAppStore.getState()
  const existing = store.blockedIPs.find((entry) => entry.ip === ip && isUnexpiredBlock(entry))
  if (existing) return { alreadyBlocked: true, record: existing }

  const blockedAt = new Date().toISOString()
  const fallbackRecord: BlockedIP = {
    id: `BLK-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    ip,
    reason,
    blockedBy: user.fullName || 'SOC Administrator',
    blockedAt,
    expiresAt,
    isActive: true,
  }

  if (supabase) {
    const { data, error } = await supabase.functions.invoke('block-ip', {
      body: { ip, reason, expires_at: expiresAt, ...(sourceAlert ? { alert_id: sourceAlert.id } : {}) },
    })
    const response = data as { ok?: boolean; error?: string; block?: unknown; audit_id?: string } | null
    if (error || !response?.ok || !response.block) {
      throw new Error(response?.error || error?.message || 'The server could not create the block.')
    }

    const record = mapBlockRow(response.block, fallbackRecord)
    useAppStore.setState((state) => ({
      blockedIPs: state.blockedIPs.some((item) => item.id === record.id) ? state.blockedIPs : [record, ...state.blockedIPs.map((item) => item.ip === ip && item.isActive && !isUnexpiredBlock(item) ? { ...item, isActive: false } : item)],
      alerts: sourceAlert ? state.alerts.map((item) => item.id === sourceAlert.id ? { ...item, status: 'blocked' } : item) : state.alerts,
    }))
    if (response.audit_id) appendLocalAudit({
      id: response.audit_id,
      userId: user.id,
      userName: user.fullName,
      action: 'blocked_ip.added',
      target: ip,
      metadata: { reason, ...(sourceAlert ? { sourceAlert: sourceAlert.id } : {}) },
      createdAt: blockedAt,
    })
    return { alreadyBlocked: false, record }
  }

  useAppStore.setState((state) => ({ blockedIPs: state.blockedIPs.map((item) => item.ip === ip && item.isActive && !isUnexpiredBlock(item) ? { ...item, isActive: false } : item) }))
  store.addBlockedIP(fallbackRecord)
  if (sourceAlert) store.updateAlert(sourceAlert.id, { status: 'blocked' })
  store.addAuditLog({
    id: `AUD-${Date.now()}`,
    userId: user.id,
    userName: user.fullName,
    action: 'blocked_ip.added',
    target: ip,
    metadata: { reason, ...(sourceAlert ? { sourceAlert: sourceAlert.id } : {}) },
    createdAt: blockedAt,
  })
  return { alreadyBlocked: false, record: fallbackRecord }
}

export async function releaseIPBlock(entry: BlockedIP, user: AppUser | null): Promise<{ alreadyUnblocked: boolean }> {
  if (user?.role !== 'admin') throw new Error('Administrator access is required to unblock an IP address.')
  if (!entry.isActive) return { alreadyUnblocked: true }
  const store = useAppStore.getState()

  if (supabase) {
    const { data, error } = await supabase.functions.invoke('block-ip', { body: { action: 'unblock', id: entry.id, ip: entry.ip } })
    const response = data as { ok?: boolean; error?: string; audit_id?: string } | null
    if (error || !response?.ok) throw new Error(response?.error || error?.message || 'The server could not release this IP block.')

    useAppStore.setState((state) => ({ blockedIPs: state.blockedIPs.map((item) => item.id === entry.id ? { ...item, isActive: false } : item) }))
    if (response.audit_id) appendLocalAudit({
      id: response.audit_id,
      userId: user.id,
      userName: user.fullName,
      action: 'blocked_ip.removed',
      target: entry.ip,
      metadata: { reason: entry.reason },
      createdAt: new Date().toISOString(),
    })
    return { alreadyUnblocked: false }
  }

  store.unblockIP(entry.id)
  store.addAuditLog({
    id: `AUD-${Date.now()}`,
    userId: user.id,
    userName: user.fullName,
    action: 'blocked_ip.removed',
    target: entry.ip,
    metadata: { reason: entry.reason },
    createdAt: new Date().toISOString(),
  })
  return { alreadyUnblocked: false }
}
