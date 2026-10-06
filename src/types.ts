export type Role = 'admin' | 'analyst' | 'viewer'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'new' | 'investigating' | 'resolved' | 'blocked'
export type IncidentStatus = 'new' | 'investigating' | 'resolved'

export interface AppUser {
  id: string
  email: string
  fullName: string
  role: Role
  avatarUrl?: string
}

export interface Alert {
  id: string
  timestamp: string
  severity: Severity
  sourceIp: string
  sourceCountry: string
  sourceLat: number | null
  sourceLng: number | null
  destinationIp: string
  protocol: string
  attackType: string
  signature: string
  status: AlertStatus
  rawLog: string
}

export interface BlockedIP {
  id: string
  ip: string
  reason: string
  blockedBy: string
  blockedAt: string
  expiresAt: string | null
  isActive: boolean
}

export interface FirewallRule {
  id: string
  name: string
  action: 'allow' | 'deny'
  protocol: string
  source: string
  destination: string
  port: string
  enabled: boolean
  createdBy: string
  createdAt: string
}

export interface Incident {
  id: string
  title: string
  description: string
  severity: Severity
  status: IncidentStatus
  assignedTo: string
  createdAt: string
  resolvedAt?: string | null
  notes: string[]
}

export interface Sensor {
  id: string
  name: string
  type: 'Suricata' | 'Zeek' | 'Wazuh'
  ip: string
  status: 'online' | 'offline' | 'warning'
  cpu: number
  memory: number
  uptime: string
  lastHeartbeat: string
}

export type PlaybookField = 'severity' | 'attack_type' | 'source_country' | 'protocol'
export type PlaybookOperator = 'equals' | 'contains' | 'greater_than'
export interface PlaybookCondition {
  field: PlaybookField
  operator: PlaybookOperator
  value: string
}

export interface Playbook {
  id: string
  name: string
  triggerCondition: string
  condition: PlaybookCondition
  actions: string[]
  enabled: boolean
  createdAt: string
}

export interface AuditLog {
  id: string
  userId: string
  userName: string
  action: string
  target: string
  metadata: Record<string, unknown>
  createdAt: string
}

export interface AppNotification {
  id: string
  userId: string
  title: string
  message: string
  type: 'critical' | 'warning' | 'success' | 'info'
  read: boolean
  createdAt: string
}
