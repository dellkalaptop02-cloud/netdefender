import type { Alert, AppNotification, AuditLog, BlockedIP, FirewallRule, Incident, Playbook, Sensor, Severity } from './types'

const now = Date.now()
const isoAgo = (minutes: number) => new Date(now - minutes * 60_000).toISOString()
const countries = [
  { name: 'Russia', lat: 55.75, lng: 37.62, ip: '185.220.101.45' },
  { name: 'China', lat: 31.23, lng: 121.47, ip: '103.74.118.23' },
  { name: 'United States', lat: 39.74, lng: -104.99, ip: '198.98.57.12' },
  { name: 'Brazil', lat: -23.55, lng: -46.63, ip: '177.54.148.77' },
  { name: 'India', lat: 19.08, lng: 72.88, ip: '45.155.205.233' },
  { name: 'Iran', lat: 35.69, lng: 51.39, ip: '91.240.118.172' },
  { name: 'North Korea', lat: 39.02, lng: 125.75, ip: '175.45.176.14' },
]
const attackTypes = ['Port Scan', 'SSH Brute Force', 'SQL Injection', 'DDoS', 'Malware C2', 'XSS', 'Ransomware', 'Zero-Day Exploit']
const protocols = ['TCP', 'TCP', 'TCP', 'UDP', 'HTTPS', 'HTTP', 'SSH']
const sigs: Record<string, string> = {
  'Port Scan': 'ET SCAN Potential SSH Scan',
  'SSH Brute Force': 'ET POLICY SSH brute force attempt',
  'SQL Injection': 'ET WEB_SERVER SQL injection attempt',
  DDoS: 'ET DOS Possible UDP amplification attack',
  'Malware C2': 'ET TROJAN C2 beacon detected',
  XSS: 'ET WEB_CLIENT Cross-site scripting attempt',
  Ransomware: 'ET MALWARE Ransomware payload delivery',
  'Zero-Day Exploit': 'ET EXPLOIT Suspicious memory corruption pattern',
}

export const seedAlerts: Alert[] = Array.from({ length: 50 }, (_, i) => {
  const source = countries[(i * 5 + Math.floor(i / 3)) % countries.length]
  const attackType = attackTypes[(i * 3 + Math.floor(i / 4)) % attackTypes.length]
  const severity: Severity = i % 13 === 0 ? 'critical' : i % 5 === 0 ? 'high' : i % 3 === 0 ? 'medium' : 'low'
  const minutesAgo = i < 8 ? i * 3 + 1 : Math.floor((i / 50) * 24 * 60)
  const id = `ALT-${String(7421 + i).padStart(5, '0')}`
  return {
    id,
    timestamp: isoAgo(minutesAgo),
    severity,
    sourceIp: i % 7 === 0 ? source.ip : `${source.ip.split('.').slice(0, 3).join('.')}.${(i * 17 + 31) % 240 + 10}`,
    sourceCountry: source.name,
    sourceLat: source.lat + ((i % 5) - 2) * 0.45,
    sourceLng: source.lng + ((i % 7) - 3) * 0.55,
    destinationIp: `10.24.${(i % 4) + 1}.${(i * 11) % 200 + 20}`,
    protocol: protocols[i % protocols.length],
    attackType,
    signature: sigs[attackType],
    status: i % 17 === 0 ? 'resolved' : i % 11 === 0 ? 'investigating' : i % 13 === 0 ? 'blocked' : 'new',
    rawLog: `[${new Date(now - minutesAgo * 60_000).toISOString()}] [**] ${sigs[attackType]} [**]\n[src=${source.ip} dst=10.24.${(i % 4) + 1}.${(i * 11) % 200 + 20} proto=${protocols[i % protocols.length]}]\n[Classification: Attempted ${attackType}] [Priority: ${severity === 'critical' ? 1 : severity === 'high' ? 2 : 3}]`,
  }
})

export const seedBlockedIPs: BlockedIP[] = [
  ['185.220.101.45', 'Automated SSH brute force', '2025-02-21T12:12:00Z', '2030-02-21T12:12:00Z'],
  ['103.74.118.23', 'SQL injection campaign', '2025-02-21T11:42:00Z', null],
  ['45.155.205.233', 'Credential stuffing source', '2025-02-21T09:15:00Z', '2026-10-06T09:15:00Z'],
  ['91.240.118.172', 'Known malicious scanner', '2025-02-20T21:18:00Z', null],
  ['177.54.148.77', 'DDoS botnet node', '2025-02-20T19:03:00Z', '2025-02-22T19:03:00Z'],
  ['175.45.176.14', 'Malware C2 beacon', '2025-02-20T17:31:00Z', null],
  ['198.98.57.12', 'Port scanning activity', '2025-02-20T16:02:00Z', '2026-10-05T20:00:00Z'],
  ['185.156.73.92', 'Repeated auth failures', '2025-02-20T14:44:00Z', '2025-02-21T14:44:00Z'],
  ['89.248.165.16', 'Exploit probing', '2025-02-20T12:24:00Z', null],
  ['194.26.29.101', 'Threat intelligence match', '2025-02-20T10:40:00Z', '2026-10-08T10:40:00Z'],
].map(([ip, reason, blockedAt, expiresAt], i) => ({
  id: `BLK-${i + 1}`,
  ip: ip as string,
  reason: reason as string,
  blockedBy: i % 2 ? 'Maya Chen' : 'Alex Morgan',
  blockedAt: blockedAt as string,
  expiresAt: expiresAt as string | null,
  isActive: i !== 4 && i !== 7,
}))

export const seedSensors: Sensor[] = [
  { id: 'SNS-01', name: 'Edge Sensor · Ashburn', type: 'Suricata', ip: '10.24.1.10', status: 'online', cpu: 32, memory: 68, uptime: '14d 06h 32m', lastHeartbeat: isoAgo(0) },
  { id: 'SNS-02', name: 'Core Monitor · Frankfurt', type: 'Zeek', ip: '10.24.2.14', status: 'online', cpu: 24, memory: 54, uptime: '8d 19h 04m', lastHeartbeat: isoAgo(0) },
  { id: 'SNS-03', name: 'Endpoint Cluster · SFO', type: 'Wazuh', ip: '10.24.3.21', status: 'warning', cpu: 82, memory: 78, uptime: '3d 12h 58m', lastHeartbeat: isoAgo(1) },
  { id: 'SNS-04', name: 'DMZ Sensor · Singapore', type: 'Suricata', ip: '10.24.4.08', status: 'offline', cpu: 0, memory: 0, uptime: '—', lastHeartbeat: isoAgo(24) },
  { id: 'SNS-05', name: 'Cloud Workloads · London', type: 'Zeek', ip: '10.24.5.16', status: 'online', cpu: 41, memory: 61, uptime: '21d 02h 11m', lastHeartbeat: isoAgo(0) },
]

export const seedFirewallRules: FirewallRule[] = [
  { id: 'FW-001', name: 'Block known threat feeds', action: 'deny', protocol: 'ANY', source: 'Threat Intel', destination: '0.0.0.0/0', port: 'ANY', enabled: true, createdBy: 'System', createdAt: isoAgo(18_000) },
  { id: 'FW-002', name: 'Allow HTTPS inbound', action: 'allow', protocol: 'TCP', source: '0.0.0.0/0', destination: '10.24.0.0/16', port: '443', enabled: true, createdBy: 'Alex Morgan', createdAt: isoAgo(14_400) },
  { id: 'FW-003', name: 'Restrict SSH access', action: 'deny', protocol: 'TCP', source: '!10.24.0.0/16', destination: '10.24.0.0/16', port: '22', enabled: true, createdBy: 'Maya Chen', createdAt: isoAgo(7_200) },
  { id: 'FW-004', name: 'Allow DNS egress', action: 'allow', protocol: 'UDP', source: '10.24.0.0/16', destination: '1.1.1.1', port: '53', enabled: true, createdBy: 'Alex Morgan', createdAt: isoAgo(3_600) },
  { id: 'FW-005', name: 'Block legacy SMB', action: 'deny', protocol: 'TCP', source: '0.0.0.0/0', destination: '10.24.0.0/16', port: '445', enabled: false, createdBy: 'Jordan Lee', createdAt: isoAgo(1_200) },
]

export const seedIncidents: Incident[] = [
  { id: 'INC-2084', title: 'Credential spray on VPN gateway', description: 'A coordinated password spray targeted the remote access gateway from multiple residential proxy networks. No successful authentication has been confirmed.', severity: 'critical', status: 'new', assignedTo: 'Maya Chen', createdAt: isoAgo(36), notes: ['Correlated 84 source IPs across 11 minutes.', 'VPN policy requires MFA on all accounts.'] },
  { id: 'INC-2083', title: 'Outbound beaconing from app tier', description: 'Repeated outbound TLS sessions to a newly registered domain were observed from the production application subnet.', severity: 'high', status: 'investigating', assignedTo: 'Alex Morgan', createdAt: isoAgo(142), notes: ['Host isolated from internet egress.', 'Endpoint triage in progress.'] },
  { id: 'INC-2081', title: 'SQL injection attempt blocked', description: 'WAF prevented a UNION-based SQL injection against the customer search endpoint. No data exposure identified.', severity: 'medium', status: 'resolved', assignedTo: 'Jordan Lee', createdAt: isoAgo(890), resolvedAt: isoAgo(370), notes: ['WAF signature updated.', 'No database anomalies found.'] },
]

export const seedPlaybooks: Playbook[] = [
  { id: 'PB-001', name: 'Auto-block critical sources', triggerCondition: 'severity = critical', condition: { field: 'severity', operator: 'equals', value: 'critical' }, actions: ['Block IP', 'Create Incident'], enabled: true, createdAt: isoAgo(42_000) },
  { id: 'PB-002', name: 'Escalate brute force', triggerCondition: 'attack_type = SSH Brute Force', condition: { field: 'attack_type', operator: 'equals', value: 'SSH Brute Force' }, actions: ['Block IP', 'Send Email', 'Slack Notify'], enabled: true, createdAt: isoAgo(32_000) },
  { id: 'PB-003', name: 'Triage SQL injection', triggerCondition: 'attack_type = SQL Injection', condition: { field: 'attack_type', operator: 'equals', value: 'SQL Injection' }, actions: ['Create Incident', 'Slack Notify'], enabled: true, createdAt: isoAgo(21_000) },
  { id: 'PB-004', name: 'Notify on high severity', triggerCondition: 'severity = high', condition: { field: 'severity', operator: 'equals', value: 'high' }, actions: ['Send Email'], enabled: false, createdAt: isoAgo(10_000) },
]

export const seedAuditLogs: AuditLog[] = [
  { id: 'AUD-091', userId: 'usr-001', userName: 'Alex Morgan', action: 'blocked_ip.added', target: '185.220.101.45', metadata: { reason: 'Automated SSH brute force' }, createdAt: isoAgo(12) },
  { id: 'AUD-090', userId: 'usr-002', userName: 'Maya Chen', action: 'incident.updated', target: 'INC-2083', metadata: { status: 'investigating' }, createdAt: isoAgo(84) },
  { id: 'AUD-089', userId: 'usr-001', userName: 'Alex Morgan', action: 'firewall_rule.toggled', target: 'FW-005', metadata: { enabled: false }, createdAt: isoAgo(231) },
  { id: 'AUD-088', userId: 'usr-003', userName: 'Jordan Lee', action: 'alert.resolved', target: 'ALT-07421', metadata: { status: 'resolved' }, createdAt: isoAgo(427) },
  { id: 'AUD-087', userId: 'usr-002', userName: 'Maya Chen', action: 'playbook.created', target: 'PB-004', metadata: { trigger: 'severity = high' }, createdAt: isoAgo(812) },
]

export const seedNotifications: AppNotification[] = [
  { id: 'NTF-1', userId: 'all', title: 'Critical alert detected', message: 'Credential spray activity from 185.220.101.45', type: 'critical', read: false, createdAt: isoAgo(4) },
  { id: 'NTF-2', userId: 'all', title: 'Sensor needs attention', message: 'Endpoint Cluster · SFO is operating above 80% CPU.', type: 'warning', read: false, createdAt: isoAgo(26) },
  { id: 'NTF-3', userId: 'all', title: 'Block list synced', message: 'Threat intelligence feed sync completed successfully.', type: 'success', read: true, createdAt: isoAgo(74) },
]
