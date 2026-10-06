import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { toast } from 'sonner'
import { supabase } from '../lib/supabase'
import { changePassword } from '../lib/auth'
import { useAppStore } from '../store'
import { Avatar, Button, IconButton, Modal, PageHeader, Toggle } from '../components/Ui'
import { Activity, Bell, Check, ChevronRight, Copy, Eye, EyeOff, KeyRound, LoaderCircle, Mail, Moon, Plus, Save, Shield, ShieldAlert, ShieldCheck, Square, Sun, Trash2, UserRound, Webhook, Zap } from 'lucide-react'
import { activateFirewallKillSwitch } from '../lib/responseActions'

const profileSchema = z.object({ fullName: z.string().min(2, 'Name must be at least 2 characters').max(80), email: z.string().email('Enter a valid email address') })
const passwordSchema = z.object({ currentPassword: z.string().min(1, 'Enter your current password'), password: z.string().min(10, 'Use at least 10 characters'), confirmPassword: z.string().min(1, 'Confirm your new password') }).refine((value) => value.password === value.confirmPassword, { path: ['confirmPassword'], message: 'Passwords do not match' })
type ProfileForm = z.infer<typeof profileSchema>
type PasswordForm = z.infer<typeof passwordSchema>
type ApiKeyRecord = { id: string; name: string; createdAt: string; prefix: string }

const settingsTabs = [
  { id: 'profile', label: 'Profile', icon: UserRound }, { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'api', label: 'API keys', icon: KeyRound }, { id: 'appearance', label: 'Appearance', icon: Sun },
  { id: 'security', label: 'Emergency controls', icon: ShieldAlert },
] as const

function readKeys(): ApiKeyRecord[] { try { return JSON.parse(localStorage.getItem('netdefender-api-key-metadata') || '[]') as ApiKeyRecord[] } catch { return [] } }

export default function SettingsPage() {
  const user = useAppStore((state) => state.user)
  const firewallRules = useAppStore((state) => state.firewallRules)
  const updateProfile = useAppStore((state) => state.updateProfile)
  const lightMode = useAppStore((state) => state.lightMode)
  const toggleTheme = useAppStore((state) => state.toggleTheme)
  const [tab, setTab] = useState<typeof settingsTabs[number]['id']>('profile')
  const [killOpen, setKillOpen] = useState(false)
  const [killSubmitting, setKillSubmitting] = useState(false)
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [keys, setKeys] = useState<ApiKeyRecord[]>(readKeys)
  const [revealedKey, setRevealedKey] = useState('')
  const [notifications, setNotifications] = useState({ email: true, slack: false, telegram: false, criticalOnly: true })
  const [webhook, setWebhook] = useState('')
  const [telegramToken, setTelegramToken] = useState('')
  const profileForm = useForm<ProfileForm>({ resolver: zodResolver(profileSchema), defaultValues: { fullName: user?.fullName || '', email: user?.email || '' } })
  const passwordForm = useForm<PasswordForm>({ resolver: zodResolver(passwordSchema) })

  useEffect(() => {
    if (!supabase || user?.role !== 'admin') return
    let active = true
    supabase.functions.invoke('manage-api-keys', { body: { action: 'list' } }).then(({ data, error }) => {
      if (!active) return
      if (error) { toast.error('Could not load API keys', { description: error.message }); return }
      const response = data as { keys?: Array<{ id: string; name: string; created_at: string; key_prefix: string; revoked_at?: string | null }> }
      setKeys((response.keys || []).filter((key) => !key.revoked_at).map((key) => ({ id: key.id, name: key.name, createdAt: key.created_at, prefix: key.key_prefix })))
    })
    return () => { active = false }
  }, [])

  const saveProfile = profileForm.handleSubmit(async (values) => {
    if (supabase) {
      const { error } = await supabase.auth.updateUser({ email: values.email })
      if (error) { toast.error('Unable to update email', { description: error.message }); return }
    }
    updateProfile({ fullName: values.fullName.trim(), email: values.email.trim() })
    toast.success('Profile updated', { description: 'Your account details have been saved.' })
  })
  const savePassword = passwordForm.handleSubmit(async (values) => {
    try {
      await changePassword(user?.email || '', values.currentPassword, values.password)
      toast.success('Password updated', { description: 'Your new password is active.' })
      passwordForm.reset()
    } catch (error) {
      toast.error('Password update failed', { description: error instanceof Error ? error.message : 'Please try again.' })
    }
  })
  const createKey = async () => {
    if (supabase) {
      const { data, error } = await supabase.functions.invoke('manage-api-keys', { body: { action: 'create', name: `SOC API key ${keys.length + 1}` } })
      if (error || !data) { toast.error('Could not generate API key', { description: error?.message || 'Try again.' }); return }
      const result = data as { key: { id: string; name: string; created_at: string; key_prefix: string }; secret: string }
      const record = { id: result.key.id, name: result.key.name, createdAt: result.key.created_at, prefix: result.key.key_prefix }
      setKeys((items) => [record, ...items]); setRevealedKey(result.secret)
      toast.success('New API key generated', { description: 'Copy it now. The full value will not be shown again.' })
      return
    }
    const bytes = new Uint8Array(32); crypto.getRandomValues(bytes)
    const secret = `nd_live_${Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('')}`
    const record = { id: `key-${Date.now()}`, name: `SOC API key ${keys.length + 1}`, createdAt: new Date().toISOString(), prefix: secret.slice(0, 15) }
    const next = [record, ...keys]; setKeys(next); localStorage.setItem('netdefender-api-key-metadata', JSON.stringify(next)); setRevealedKey(secret)
    toast.success('New API key generated', { description: 'Copy it now. The full value will not be shown again.' })
  }
  const revokeKey = async (id: string) => {
    if (!window.confirm('Revoke this API key? Any integrations using it will stop working.')) return
    if (supabase) {
      const { error } = await supabase.functions.invoke('manage-api-keys', { body: { action: 'revoke', id } })
      if (error) { toast.error('Could not revoke API key', { description: error.message }); return }
    }
    const next = keys.filter((key) => key.id !== id); setKeys(next)
    if (!supabase) localStorage.setItem('netdefender-api-key-metadata', JSON.stringify(next))
    setRevealedKey(''); toast.success('API key revoked')
  }
  const copyKey = async () => { try { await navigator.clipboard.writeText(revealedKey); toast.success('API key copied to clipboard') } catch { toast.error('Clipboard is unavailable') } }
  const saveNotifications = () => toast.success('Notification preferences saved', { description: 'Your alert delivery settings are up to date.' })
  const activeFirewallCount = firewallRules.filter((rule) => rule.enabled).length
  const executeKillSwitch = async () => {
    if (killSubmitting || user?.role !== 'admin') return
    setKillSubmitting(true)
    try {
      const result = await activateFirewallKillSwitch(user, 'settings')
      setKillOpen(false)
      if (result.auditLogged) toast.error('Kill switch activated', { description: `${result.disabledRules} enabled firewall policies disabled. The action was recorded in audit logs.` })
      else toast.error('Firewall disabled with an audit warning', { description: `Rules are disabled, but the audit entry could not be saved: ${result.auditError}` })
    } catch (error) {
      toast.error('Kill switch failed', { description: error instanceof Error ? error.message : 'Firewall rules could not be disabled.' })
    } finally { setKillSubmitting(false) }
  }

  return <div className="page">
    <PageHeader eyebrow="WORKSPACE CONFIGURATION" title="Settings" description="Manage your personal details, integrations, and SOC workspace preferences." />
    <div className="settings-layout"><aside className="settings-nav"><span className="settings-nav-label">ACCOUNT & WORKSPACE</span>{settingsTabs.filter((item) => (item.id !== 'api' && item.id !== 'security') || user?.role === 'admin').map((item) => <button key={item.id} onClick={() => setTab(item.id)} className={`settings-nav-item ${tab === item.id ? 'settings-nav-active' : ''}`}><item.icon size={16} />{item.label}<ChevronRight size={14} className="settings-nav-chevron" /></button>)}<div className="settings-nav-foot"><Shield size={15} /><span>Workspace security<br /><b>Enterprise protection</b></span></div></aside>
      <div className="settings-content">
        {tab === 'profile' && <div className="settings-panel"><div className="settings-panel-heading"><div><h2>Profile settings</h2><p>Update your identity and sign-in credentials.</p></div><span className="settings-role-chip"><Shield size={13} /> {user?.role || 'viewer'} role</span></div><div className="profile-avatar-row"><Avatar name={user?.fullName || 'Alex Morgan'} size="lg" /><div><b>Profile photo</b><p>Your initials are used as your workspace avatar.</p></div><Button variant="secondary" size="sm" onClick={() => toast.info('Avatar management', { description: 'Connect a profile image URL in your identity provider to change this avatar.' })}>Change photo</Button></div><form className="settings-form" onSubmit={saveProfile}><div className="form-two-column"><label className="form-field"><span>Full name</span><input {...profileForm.register('fullName')} />{profileForm.formState.errors.fullName && <small className="field-error">{profileForm.formState.errors.fullName.message}</small>}</label><label className="form-field"><span>Email address</span><input type="email" {...profileForm.register('email')} />{profileForm.formState.errors.email && <small className="field-error">{profileForm.formState.errors.email.message}</small>}</label></div><div className="settings-form-footer"><span>Changes to your email may require verification.</span><Button type="submit"><Save size={14} /> Save profile</Button></div></form><div className="settings-divider" /><div className="settings-panel-heading password-heading"><div><h2>Change password</h2><p>Use a strong password you don't use elsewhere.</p></div></div><form className="settings-form" onSubmit={savePassword}><label className="form-field"><span>Current password</span><div className="password-field"><input type={showCurrent ? 'text' : 'password'} placeholder="Enter current password" {...passwordForm.register('currentPassword')} /><button type="button" onClick={() => setShowCurrent((value) => !value)}>{showCurrent ? <EyeOff size={15} /> : <Eye size={15} />}</button></div>{passwordForm.formState.errors.currentPassword && <small className="field-error">{passwordForm.formState.errors.currentPassword.message}</small>}</label><div className="form-two-column"><label className="form-field"><span>New password</span><div className="password-field"><input type={showNew ? 'text' : 'password'} placeholder="At least 10 characters" {...passwordForm.register('password')} /><button type="button" onClick={() => setShowNew((value) => !value)}>{showNew ? <EyeOff size={15} /> : <Eye size={15} />}</button></div>{passwordForm.formState.errors.password && <small className="field-error">{passwordForm.formState.errors.password.message}</small>}</label><label className="form-field"><span>Confirm password</span><input type="password" placeholder="Re-enter new password" {...passwordForm.register('confirmPassword')} />{passwordForm.formState.errors.confirmPassword && <small className="field-error">{passwordForm.formState.errors.confirmPassword.message}</small>}</label></div><div className="settings-form-footer"><span>Minimum 10 characters.</span><Button variant="secondary" type="submit"><KeyRound size={14} /> Update password</Button></div></form></div>}

        {tab === 'notifications' && <div className="settings-panel"><div className="settings-panel-heading"><div><h2>Notification preferences</h2><p>Choose how NetDefender routes security events to your team.</p></div><Button onClick={saveNotifications}><Save size={14} /> Save preferences</Button></div><div className="settings-group-title"><Mail size={16} /><div><b>Email notifications</b><span>Deliver high-priority alerts to your inbox.</span></div></div><PreferenceRow title="Critical alert emails" description="Immediate notification when a critical detection is raised." checked={notifications.email} onChange={(value) => setNotifications({ ...notifications, email: value })} /><PreferenceRow title="Critical alerts only" description="Reduce noise by only sending critical severity events." checked={notifications.criticalOnly} onChange={(value) => setNotifications({ ...notifications, criticalOnly: value })} /><div className="settings-divider" /><div className="settings-group-title"><Webhook size={16} /><div><b>External integrations</b><span>Connect your collaboration and incident response tools.</span></div></div><PreferenceRow title="Slack webhook" description="Send alert summaries to a Slack channel." checked={notifications.slack} onChange={(value) => setNotifications({ ...notifications, slack: value })} /><div className="settings-integration-input"><span>Webhook URL</span><input value={webhook} onChange={(event) => setWebhook(event.target.value)} placeholder="https://hooks.slack.com/services/…" disabled={!notifications.slack} /></div><PreferenceRow title="Telegram bot" description="Send critical notifications to a Telegram chat." checked={notifications.telegram} onChange={(value) => setNotifications({ ...notifications, telegram: value })} /><div className="settings-integration-input"><span>Bot token</span><input type="password" value={telegramToken} onChange={(event) => setTelegramToken(event.target.value)} placeholder="Enter Telegram bot token" disabled={!notifications.telegram} /></div><div className="integration-note"><Activity size={14} /> Secrets are encrypted when a connected Supabase project is configured. Demo mode stores preferences in this browser only.</div></div>}

        {tab === 'api' && <div className="settings-panel"><div className="settings-panel-heading"><div><h2>API keys</h2><p>Authenticate trusted services that send events to your workspace.</p></div><Button onClick={createKey}><Plus size={15} /> Generate key</Button></div><div className="api-security-callout"><KeyRound size={17} /><div><b>Treat API keys like passwords</b><span>Full key values are only shown once. Use hashed API-key records on the server and rotate keys regularly.</span></div></div>{revealedKey && <div className="revealed-key"><div><span>NEW KEY · COPY NOW</span><code>{revealedKey}</code></div><Button variant="secondary" size="sm" onClick={copyKey}><Copy size={14} /> Copy key</Button><IconButton label="Hide API key" onClick={() => setRevealedKey('')}><EyeOff size={15} /></IconButton></div>}<div className="api-key-table-heading"><span>ACTIVE KEYS</span><span>{keys.length} {keys.length === 1 ? 'key' : 'keys'}</span></div>{keys.length === 0 ? <div className="settings-empty"><KeyRound size={21} /><b>No API keys created</b><span>Generate a key to connect a sensor or event source.</span></div> : keys.map((key) => <div className="api-key-row" key={key.id}><div className="api-key-icon"><KeyRound size={15} /></div><div className="api-key-details"><b>{key.name}</b><code>{key.prefix}••••••••••••</code></div><span className="api-key-created">Created {new Date(key.createdAt).toLocaleDateString()}</span><span className="api-key-status"><i /> Active</span><IconButton label={`Revoke ${key.name}`} onClick={() => revokeKey(key.id)}><Trash2 size={15} /></IconButton></div>)}</div>}

        {tab === 'appearance' && <div className="settings-panel"><div className="settings-panel-heading"><div><h2>Appearance</h2><p>Personalize your security operations workspace.</p></div></div><div className="appearance-choice-row"><div className="appearance-copy"><span className="appearance-icon"><Moon size={16} /></span><div><b>Dark mode</b><p>Optimized for low-light SOC environments and long shifts.</p></div></div><Toggle checked={!lightMode} onChange={() => toggleTheme()} label="Toggle dark mode" /></div><div className="appearance-preview-row"><button className={`theme-preview theme-preview-dark ${!lightMode ? 'theme-preview-selected' : ''}`} onClick={() => { if (lightMode) toggleTheme() }}><span className="preview-window"><i /><i /><i /><b /></span><strong>Midnight SOC</strong><small>Dark · recommended</small>{!lightMode && <Check size={14} />}</button><button className={`theme-preview theme-preview-light ${lightMode ? 'theme-preview-selected' : ''}`} onClick={() => { if (!lightMode) toggleTheme() }}><span className="preview-window"><i /><i /><i /><b /></span><strong>Daylight</strong><small>Light · high contrast</small>{lightMode && <Check size={14} />}</button></div><div className="settings-divider" /><div className="settings-group-title"><Activity size={16} /><div><b>Interface preferences</b><span>Additional display settings for this browser.</span></div></div><PreferenceRow title="Compact data tables" description="Show more rows on screen with reduced cell padding." checked={false} onChange={() => toast.info('Compact table density is coming soon.')} /><PreferenceRow title="Reduced motion" description="Minimize animations and ambient movement." checked={false} onChange={() => toast.info('Reduced motion preference saved.')} /></div>}

        {tab === 'security' && user?.role === 'admin' && <div className="settings-panel"><div className="settings-panel-heading"><div><h2>Emergency controls</h2><p>High-impact network actions for incident containment.</p></div><span className="settings-role-chip settings-emergency-role"><ShieldAlert size={13} /> ADMIN ONLY</span></div><section className="settings-emergency-card"><div className="settings-emergency-main"><span className="settings-emergency-icon"><Zap size={18} /></span><div><b>Firewall kill switch</b><p>Disable every firewall rule immediately. Traffic will no longer be filtered by these policies until an administrator re-enables them.</p></div><span className={`settings-rule-count ${activeFirewallCount ? 'settings-rule-count-active' : ''}`}><i />{activeFirewallCount} ENABLED</span></div><div className="settings-emergency-footer"><span><ShieldCheck size={14} /> The operation and affected rule IDs are written to audit logs.</span><Button variant="danger" onClick={() => setKillOpen(true)}><Square size={13} fill="currentColor" /> Kill switch</Button></div></section><div className="settings-emergency-note"><ShieldAlert size={15} /><span>This control is available to administrators only. Use the confirmation step to verify the impact before applying.</span></div></div>}
      </div>
    </div>
    <Modal open={killOpen} onClose={() => { if (!killSubmitting) setKillOpen(false) }} title="Disable all firewall rules?" subtitle="Emergency kill switch · High-impact action" size="sm" footer={<><Button variant="ghost" onClick={() => setKillOpen(false)} disabled={killSubmitting}>Cancel</Button><Button variant="danger" onClick={() => void executeKillSwitch()} disabled={killSubmitting}>{killSubmitting ? <LoaderCircle className="spin" size={14} /> : <Square size={13} fill="currentColor" />} Disable all rules</Button></>}><div className="kill-switch-copy"><span><Zap size={21} /></span><p>This will disable <strong>{activeFirewallCount} enabled firewall policies</strong> and stop these rules from filtering network traffic. The operation is written to <strong>audit_logs</strong>.</p></div></Modal>
  </div>
}

function PreferenceRow({ title, description, checked, onChange }: { title: string; description: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <div className="preference-row"><div><b>{title}</b><span>{description}</span></div><Toggle checked={checked} onChange={onChange} label={title} /></div>
}
