import { supabase } from './supabase'
import type { AppUser, Role } from '../types'

type LocalAccount = { email: string; passwordHash: string; fullName: string; role: Role; id: string }
const ACCOUNTS_KEY = 'netdefender-local-accounts'
const DEMO_EMAIL = 'admin@netdefender.io'
const DEMO_PASSWORD = 'NetDefender!2026'

async function hashPassword(value: string) {
  const bytes = new TextEncoder().encode(value)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}
function readAccounts(): LocalAccount[] {
  try { return JSON.parse(localStorage.getItem(ACCOUNTS_KEY) || '[]') as LocalAccount[] } catch { return [] }
}
function toAppUser(value: { id: string; email: string; fullName?: string; role?: Role }): AppUser {
  return { id: value.id, email: value.email, fullName: value.fullName || value.email.split('@')[0], role: value.role || 'viewer' }
}

export async function signInWithEmail(email: string, password: string): Promise<AppUser> {
  if (supabase) {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password })
    if (error) throw error
    const { data: profileData } = await supabase.from('profiles').select('full_name, role').eq('id', data.user.id).maybeSingle()
    const profile = profileData as unknown as { full_name?: string; role?: Role } | null
    return toAppUser({ id: data.user.id, email: data.user.email || email, fullName: profile?.full_name, role: profile?.role })
  }

  const normalizedEmail = email.trim().toLowerCase()
  const passwordHash = await hashPassword(password)
  if (normalizedEmail === DEMO_EMAIL) {
    const storedDemoHash = localStorage.getItem('netdefender-demo-password-hash') || await hashPassword(DEMO_PASSWORD)
    if (passwordHash === storedDemoHash) return toAppUser({ id: 'demo-admin-001', email: DEMO_EMAIL, fullName: 'Alex Morgan', role: 'admin' })
  }
  const account = readAccounts().find((entry) => entry.email === normalizedEmail && entry.passwordHash === passwordHash)
  if (!account) throw new Error('Invalid email or password. Try the demo account or create a new workspace user.')
  return toAppUser(account)
}

export async function signUpWithEmail(email: string, password: string, fullName: string): Promise<{ user: AppUser; requiresConfirmation: boolean }> {
  if (supabase) {
    const { data, error } = await supabase.auth.signUp({ email, password, options: { data: { full_name: fullName } } })
    if (error) throw error
    if (!data.user) throw new Error('Signup did not return a user. Please try again.')
    return { user: toAppUser({ id: data.user.id, email: data.user.email || email, fullName, role: 'viewer' }), requiresConfirmation: !data.session }
  }

  const normalizedEmail = email.trim().toLowerCase()
  const accounts = readAccounts()
  if (normalizedEmail === DEMO_EMAIL || accounts.some((account) => account.email === normalizedEmail)) {
    throw new Error('An account with this email already exists.')
  }
  const account: LocalAccount = { id: crypto.randomUUID(), email: normalizedEmail, passwordHash: await hashPassword(password), fullName: fullName.trim(), role: 'viewer' }
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify([...accounts, account]))
  return { user: toAppUser(account), requiresConfirmation: false }
}

export async function changePassword(email: string, currentPassword: string, newPassword: string): Promise<void> {
  if (supabase) {
    const { error: verifyError } = await supabase.auth.signInWithPassword({ email, password: currentPassword })
    if (verifyError) throw new Error('Current password is incorrect.')
    const { error } = await supabase.auth.updateUser({ password: newPassword })
    if (error) throw error
    return
  }
  const normalizedEmail = email.trim().toLowerCase()
  const currentHash = await hashPassword(currentPassword)
  const nextHash = await hashPassword(newPassword)
  if (normalizedEmail === DEMO_EMAIL) {
    const stored = localStorage.getItem('netdefender-demo-password-hash') || await hashPassword(DEMO_PASSWORD)
    if (stored !== currentHash) throw new Error('Current password is incorrect.')
    localStorage.setItem('netdefender-demo-password-hash', nextHash)
    return
  }
  const accounts = readAccounts()
  const index = accounts.findIndex((account) => account.email === normalizedEmail && account.passwordHash === currentHash)
  if (index < 0) throw new Error('Current password is incorrect.')
  accounts[index] = { ...accounts[index], passwordHash: nextHash }
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts))
}

export async function requestPasswordReset(email: string): Promise<void> {
  if (supabase) {
    const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo: `${window.location.origin}/login?mode=update-password` })
    if (error) throw error
    return
  }
  // Demo-mode recovery is confined to this browser and has no outbound email provider.
  await new Promise((resolve) => setTimeout(resolve, 250))
  const normalizedEmail = email.trim().toLowerCase()
  const exists = normalizedEmail === DEMO_EMAIL || readAccounts().some((account) => account.email === normalizedEmail)
  if (exists) localStorage.setItem('netdefender-pending-reset-email', normalizedEmail)
}

export async function resetDemoPassword(newPassword: string): Promise<void> {
  const email = localStorage.getItem('netdefender-pending-reset-email')
  if (!email) throw new Error('This reset request has expired. Request a new password reset.')
  const nextHash = await hashPassword(newPassword)
  if (email === DEMO_EMAIL) localStorage.setItem('netdefender-demo-password-hash', nextHash)
  else {
    const accounts = readAccounts()
    const index = accounts.findIndex((account) => account.email === email)
    if (index < 0) throw new Error('This reset request has expired. Request a new password reset.')
    accounts[index] = { ...accounts[index], passwordHash: nextHash }
    localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts))
  }
  localStorage.removeItem('netdefender-pending-reset-email')
}

export async function signOutUser() {
  if (supabase) await supabase.auth.signOut()
}

export const DEMO_CREDENTIALS = { email: DEMO_EMAIL, password: DEMO_PASSWORD }
