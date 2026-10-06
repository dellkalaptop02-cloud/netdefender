import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { ArrowLeft, ArrowRight, CheckCircle2, Eye, EyeOff, Fingerprint, KeyRound, LoaderCircle, LockKeyhole, Mail, Shield, ShieldCheck, Sparkles } from 'lucide-react'
import { useAppStore } from '../store'
import { DEMO_CREDENTIALS, requestPasswordReset, resetDemoPassword, signInWithEmail, signUpWithEmail } from '../lib/auth'
import { hasSupabase, supabase } from '../lib/supabase'
import { BrandLogo, Button } from '../components/Ui'

const loginSchema = z.object({ email: z.string().email('Enter a valid email'), password: z.string().min(1, 'Password is required') })
const signupSchema = z.object({ fullName: z.string().min(2, 'Enter your full name'), email: z.string().email('Enter a valid email'), password: z.string().min(10, 'Use at least 10 characters') })
const resetSchema = z.object({ email: z.string().email('Enter a valid email') })
const updateSchema = z.object({ password: z.string().min(10, 'Use at least 10 characters'), confirmPassword: z.string().min(1, 'Confirm your new password') }).refine((data) => data.password === data.confirmPassword, { path: ['confirmPassword'], message: 'Passwords do not match' })
type LoginForm = z.infer<typeof loginSchema>
type SignupForm = z.infer<typeof signupSchema>
type ResetForm = z.infer<typeof resetSchema>
type UpdateForm = z.infer<typeof updateSchema>

export default function LoginPage() {
  const user = useAppStore((state) => state.user)
  const setUser = useAppStore((state) => state.setUser)
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [mode, setMode] = useState<'login' | 'signup' | 'reset' | 'update'>(searchParams.get('mode') === 'update-password' ? 'update' : 'login')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [resetSent, setResetSent] = useState(false)
  const loginForm = useForm<LoginForm>({ resolver: zodResolver(loginSchema), defaultValues: { email: hasSupabase ? '' : DEMO_CREDENTIALS.email, password: hasSupabase ? '' : DEMO_CREDENTIALS.password } })
  const signupForm = useForm<SignupForm>({ resolver: zodResolver(signupSchema) })
  const resetForm = useForm<ResetForm>({ resolver: zodResolver(resetSchema) })
  const updateForm = useForm<UpdateForm>({ resolver: zodResolver(updateSchema) })

  if (user && (mode === 'login' || mode === 'signup')) return <Navigate to="/" replace />
  const signIn = loginForm.handleSubmit(async (values) => {
    setBusy(true)
    try { const nextUser = await signInWithEmail(values.email, values.password); setUser(nextUser); toast.success(`Welcome back, ${nextUser.fullName.split(' ')[0]}`); navigate('/') }
    catch (error) { toast.error('Sign in failed', { description: error instanceof Error ? error.message : 'Check your details and try again.' }) }
    finally { setBusy(false) }
  })
  const signUp = signupForm.handleSubmit(async (values) => {
    setBusy(true)
    try {
      const result = await signUpWithEmail(values.email, values.password, values.fullName)
      if (result.requiresConfirmation) { toast.success('Account created', { description: 'Check your inbox to confirm your email, then sign in.' }); setMode('login'); loginForm.setValue('email', values.email) }
      else { setUser(result.user); toast.success('Workspace account created', { description: 'Your viewer account is ready.' }); navigate('/') }
    } catch (error) { toast.error('Could not create account', { description: error instanceof Error ? error.message : 'Please try again.' }) }
    finally { setBusy(false) }
  })
  const sendReset = resetForm.handleSubmit(async ({ email }) => {
    setBusy(true)
    try { await requestPasswordReset(email); setResetSent(true); toast.success('If your account exists, password reset instructions are ready.') }
    catch (error) { toast.error('Could not send reset instructions', { description: error instanceof Error ? error.message : 'Please try again.' }) }
    finally { setBusy(false) }
  })
  const updatePassword = updateForm.handleSubmit(async (values) => {
    setBusy(true)
    try {
      if (supabase) { const { error } = await supabase.auth.updateUser({ password: values.password }); if (error) throw error }
      else await resetDemoPassword(values.password)
      toast.success('Password updated', { description: 'You can now sign in with your new password.' }); setMode('login'); loginForm.reset({ email: '', password: '' }); navigate('/login')
    } catch (error) { toast.error('Password update failed', { description: error instanceof Error ? error.message : 'Your reset session may have expired.' }) }
    finally { setBusy(false) }
  })

  const setModeFromReset = () => { setResetSent(false); resetForm.reset(); setMode('reset') }

  return <div className="auth-page">
    <div className="auth-grid-overlay" />
    <aside className="auth-visual"><div className="auth-visual-top"><BrandLogo /><span><i className="pulse-dot" /> SOC PLATFORM · ONLINE</span></div><div className="auth-visual-content"><div className="auth-security-art"><div className="art-orbit art-orbit-a" /><div className="art-orbit art-orbit-b" /><div className="art-orbit art-orbit-c" /><div className="art-core"><ShieldCheck size={55} strokeWidth={1.15} /><span className="art-lock"><LockKeyhole size={17} /></span></div><i className="art-node art-node-a" /><i className="art-node art-node-b" /><i className="art-node art-node-c" /><i className="art-node art-node-d" /><span className="art-corner art-corner-a" /><span className="art-corner art-corner-b" /></div><div className="auth-hero-copy"><span className="auth-hero-eyebrow"><Sparkles size={13} /> PROACTIVE THREAT DEFENSE</span><h1>See the threat.<br /><span>Stop it in its tracks.</span></h1><p>Every packet. Every second. Every threat.<br />One command center for your security operations.</p></div><div className="auth-trust-row"><span><Shield size={14} /> Real-time detection</span><span><Fingerprint size={14} /> Role-based access</span><span><KeyRound size={14} /> Secure by design</span></div></div><div className="auth-visual-bottom"><span>NETDEFENDER SECURITY PLATFORM</span><span>v2.4.0 · © 2026</span></div></aside>
    <main className="auth-main"><div className="auth-card-wrap"><div className="auth-mobile-logo"><BrandLogo /></div><div className="auth-card">
      {mode === 'login' && <><div className="auth-card-heading"><div className="auth-mini-icon"><ShieldCheck size={19} /></div><span className="auth-eyebrow">SECURE ACCESS PORTAL</span><h2>Welcome back</h2><p>Sign in to your NetDefender workspace.</p></div><form className="auth-form" onSubmit={signIn}><label className="form-field"><span>Work email</span><div className="auth-input"><Mail size={15} /><input type="email" placeholder="you@company.com" autoComplete="email" {...loginForm.register('email')} /></div>{loginForm.formState.errors.email && <small className="field-error">{loginForm.formState.errors.email.message}</small>}</label><label className="form-field"><span>Password <button type="button" className="inline-auth-link" onClick={setModeFromReset}>Forgot password?</button></span><div className="auth-input"><LockKeyhole size={15} /><input type={showPassword ? 'text' : 'password'} placeholder="Enter your password" autoComplete="current-password" {...loginForm.register('password')} /><button type="button" className="show-password" onClick={() => setShowPassword((value) => !value)} aria-label="Toggle password visibility">{showPassword ? <EyeOff size={15} /> : <Eye size={15} />}</button></div>{loginForm.formState.errors.password && <small className="field-error">{loginForm.formState.errors.password.message}</small>}</label><Button type="submit" size="lg" className="auth-submit" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : <span>Sign in securely</span>} {!busy && <ArrowRight size={16} />}</Button></form><div className="auth-form-separator"><span /> <small>OR CONTINUE WITH</small> <span /></div><button className="demo-access-button" onClick={() => { loginForm.setValue('email', DEMO_CREDENTIALS.email); loginForm.setValue('password', DEMO_CREDENTIALS.password); if (!hasSupabase) { signInWithEmail(DEMO_CREDENTIALS.email, DEMO_CREDENTIALS.password).then((demoUser) => { setUser(demoUser); navigate('/') }) } }}><div className="demo-access-icon"><ShieldCheck size={16} /></div><span><b>Enter demo workspace</b><small>Explore with seeded security telemetry</small></span><ArrowRight size={15} /></button><p className="auth-switch">New to NetDefender? <button onClick={() => setMode('signup')}>Create an account</button></p>{!hasSupabase && <div className="demo-credentials"><span>DEMO ACCESS</span><code>{DEMO_CREDENTIALS.email}</code><i>·</i><code>NetDefender!2026</code></div>}</>}

      {mode === 'signup' && <><button className="auth-back-link" onClick={() => setMode('login')}><ArrowLeft size={14} /> Back to sign in</button><div className="auth-card-heading"><div className="auth-mini-icon"><ShieldCheck size={19} /></div><span className="auth-eyebrow">CREATE YOUR WORKSPACE</span><h2>Get started</h2><p>Create your NetDefender operator account.</p></div><form className="auth-form" onSubmit={signUp}><label className="form-field"><span>Full name</span><div className="auth-input"><Fingerprint size={15} /><input placeholder="Alex Morgan" autoComplete="name" {...signupForm.register('fullName')} /></div>{signupForm.formState.errors.fullName && <small className="field-error">{signupForm.formState.errors.fullName.message}</small>}</label><label className="form-field"><span>Work email</span><div className="auth-input"><Mail size={15} /><input type="email" placeholder="you@company.com" autoComplete="email" {...signupForm.register('email')} /></div>{signupForm.formState.errors.email && <small className="field-error">{signupForm.formState.errors.email.message}</small>}</label><label className="form-field"><span>Password</span><div className="auth-input"><LockKeyhole size={15} /><input type={showPassword ? 'text' : 'password'} placeholder="At least 10 characters" autoComplete="new-password" {...signupForm.register('password')} /><button type="button" className="show-password" onClick={() => setShowPassword((value) => !value)} aria-label="Toggle password visibility">{showPassword ? <EyeOff size={15} /> : <Eye size={15} />}</button></div>{signupForm.formState.errors.password && <small className="field-error">{signupForm.formState.errors.password.message}</small>}</label><Button type="submit" size="lg" className="auth-submit" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : 'Create secure account'}{!busy && <ArrowRight size={16} />}</Button></form><p className="auth-switch">Already have an account? <button onClick={() => setMode('login')}>Sign in</button></p><div className="auth-legal">By continuing, you agree to the NetDefender acceptable use policy.</div></>}

      {mode === 'reset' && <><button className="auth-back-link" onClick={() => { setMode('login'); setResetSent(false) }}><ArrowLeft size={14} /> Back to sign in</button><div className="auth-card-heading"><div className="auth-mini-icon"><KeyRound size={19} /></div><span className="auth-eyebrow">ACCOUNT RECOVERY</span><h2>Reset your password</h2><p>We'll send instructions to your registered work email.</p></div>{!resetSent ? <form className="auth-form" onSubmit={sendReset}><label className="form-field"><span>Work email</span><div className="auth-input"><Mail size={15} /><input type="email" placeholder="you@company.com" {...resetForm.register('email')} /></div>{resetForm.formState.errors.email && <small className="field-error">{resetForm.formState.errors.email.message}</small>}</label><Button type="submit" size="lg" className="auth-submit" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : 'Send reset instructions'}{!busy && <ArrowRight size={16} />}</Button></form> : <div className="reset-success"><CheckCircle2 size={27} /><b>Check your inbox</b><p>If the address is registered, reset instructions have been sent. Follow the secure link to choose a new password.</p>{!hasSupabase && localStorage.getItem('netdefender-pending-reset-email') && <Button variant="secondary" onClick={() => setMode('update')}>Set a new password <ArrowRight size={14} /></Button>}</div>}<p className="auth-switch">Remembered it? <button onClick={() => setMode('login')}>Return to sign in</button></p></>}

      {mode === 'update' && <><button className="auth-back-link" onClick={() => setMode('login')}><ArrowLeft size={14} /> Back to sign in</button><div className="auth-card-heading"><div className="auth-mini-icon"><KeyRound size={19} /></div><span className="auth-eyebrow">SECURE ACCOUNT RECOVERY</span><h2>Choose a new password</h2><p>Set a strong password for your NetDefender account.</p></div><form className="auth-form" onSubmit={updatePassword}><label className="form-field"><span>New password</span><div className="auth-input"><LockKeyhole size={15} /><input type="password" placeholder="At least 10 characters" autoComplete="new-password" {...updateForm.register('password')} /></div>{updateForm.formState.errors.password && <small className="field-error">{updateForm.formState.errors.password.message}</small>}</label><label className="form-field"><span>Confirm new password</span><div className="auth-input"><LockKeyhole size={15} /><input type="password" placeholder="Re-enter your password" autoComplete="new-password" {...updateForm.register('confirmPassword')} /></div>{updateForm.formState.errors.confirmPassword && <small className="field-error">{updateForm.formState.errors.confirmPassword.message}</small>}</label><Button type="submit" size="lg" className="auth-submit" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : 'Update password'}{!busy && <CheckCircle2 size={16} />}</Button></form><div className="auth-legal">Password must be at least 10 characters.</div></>}
      <div className="auth-card-secure"><LockKeyhole size={12} /> Protected by encrypted authentication <span>·</span> SOC-grade security</div>
    </div><div className="auth-bottom-links"><Link to="/docs">Documentation</Link><span>·</span><button onClick={() => toast.info('Support center', { description: 'Contact your workspace administrator for support.' })}>Support</button><span>·</span><span>Privacy</span></div></div></main>
  </div>
}
