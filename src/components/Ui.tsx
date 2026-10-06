import { useEffect, useId, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { Shield, ShieldCheck, X } from 'lucide-react'
import { cn, initials, severityLabel } from '../lib/utils'
import type { Severity } from '../types'

export function BrandLogo({ compact = false }: { compact?: boolean }) {
  const gradientId = `brand-shield-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`
  return <div className={cn('brand-lockup', compact && 'brand-lockup--compact')} role="img" aria-label="NetDefender">
    <div className="brand-mark" aria-hidden="true">
      <span className="brand-glow" />
      <Shield className="brand-shield" size={32} strokeWidth={1.9} stroke={`url(#${gradientId})`} aria-hidden="true" focusable="false">
        <defs><linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stopColor="#22d3ee" /><stop offset="100%" stopColor="#10b981" /></linearGradient></defs>
      </Shield>
    </div>
    {!compact && <div className="brand-wordmark"><span>NET</span><b>DEFENDER</b></div>}
  </div>
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge severity-${severity}`}><i />{severityLabel[severity]}</span>
}

export function StatusBadge({ status }: { status: string }) {
  const key = status.toLowerCase().replace(/\s/g, '-')
  return <span className={`status-badge status-${key}`}><i />{status.replace(/-/g, ' ')}</span>
}

export function LiveIndicator({ connected, className }: { connected: boolean; className?: string }) {
  return <span className={cn('live-chip', 'live-chip-small', !connected && 'live-chip-offline', className)} role="status" aria-live="polite" aria-label={connected ? 'Realtime connected' : 'Realtime reconnecting'}>
    <i className={connected ? 'pulse-dot' : 'status-dot warning-dot'} />{connected ? 'LIVE' : 'RECONNECTING'}
  </span>
}

export function Button({ children, variant = 'primary', size = 'md', className, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'subtle'; size?: 'sm' | 'md' | 'lg' }) {
  return <button className={cn('button', `button-${variant}`, `button-${size}`, className)} {...props}>{children}</button>
}

export function IconButton({ children, label, className, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return <button aria-label={label} title={label} className={cn('icon-button', className)} {...props}>{children}</button>
}

export function Modal({ open, onClose, title, subtitle, children, size = 'md', footer }: { open: boolean; onClose: () => void; title: string; subtitle?: string; children: ReactNode; size?: 'sm' | 'md' | 'lg'; footer?: ReactNode }) {
  useEffect(() => {
    if (!open) return
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [open, onClose])
  if (!open) return null
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <section className={`modal-panel modal-${size}`} role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div className="modal-heading">
        <div><h2 id="modal-title">{title}</h2>{subtitle && <p>{subtitle}</p>}</div>
        <IconButton label="Close dialog" onClick={onClose}><X size={18} /></IconButton>
      </div>
      <div className="modal-content">{children}</div>
      {footer && <div className="modal-footer">{footer}</div>}
    </section>
  </div>
}

export function Toggle({ checked, onChange, label, disabled = false }: { checked: boolean; onChange: (value: boolean) => void; label?: string; disabled?: boolean }) {
  return <button type="button" role="switch" aria-checked={checked} aria-label={label || 'Toggle'} disabled={disabled} className={cn('toggle', checked && 'toggle-on')} onClick={() => onChange(!checked)}><span /></button>
}

export function Avatar({ name, size = 'md', online = false }: { name: string; size?: 'sm' | 'md' | 'lg'; online?: boolean }) {
  const colors = ['avatar-cyan', 'avatar-violet', 'avatar-emerald', 'avatar-blue']
  const tint = colors[name.charCodeAt(0) % colors.length]
  return <span className={cn('avatar', `avatar-${size}`, tint)}>{initials(name)}{online && <i className="avatar-online" />}</span>
}

export function PageHeader({ title, description, eyebrow, actions }: { title: string; description?: string; eyebrow?: string; actions?: ReactNode }) {
  return <div className="page-header">
    <div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<h1>{title}</h1>{description && <p>{description}</p>}</div>
    {actions && <div className="page-header-actions">{actions}</div>}
  </div>
}

export function SectionTitle({ title, subtitle, action, icon }: { title: string; subtitle?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return <div className="section-title">
    <div className="section-title-left">{icon && <span className="section-title-icon">{icon}</span>}<div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div></div>
    {action}
  </div>
}

export function EmptyState({ title, description, action, icon, compact = false }: { title: string; description: string; action?: ReactNode; icon?: ReactNode; compact?: boolean }) {
  return <div className={`empty-state ${compact ? 'empty-state-compact' : ''}`}>
    <div className="empty-illustration">{icon || <ShieldCheck size={30} />}<span /></div>
    <h3>{title}</h3><p>{description}</p>{action && <div className="empty-state-actions">{action}</div>}
  </div>
}

export function Skeleton({ className = '' }: { className?: string }) { return <div className={`skeleton ${className}`} aria-hidden="true" /> }

export function PageSkeleton({ compact = false }: { compact?: boolean }) {
  return <div className={`page-skeleton ${compact ? 'page-skeleton-compact' : ''}`} role="status" aria-busy="true" aria-label="Loading page content">
    <div className={`page-skeleton-brand ${compact ? 'page-skeleton-brand-compact' : ''}`}><BrandLogo compact={compact} /></div>
    <div className="page-skeleton-heading"><div><Skeleton className="skeleton-eyebrow" /><Skeleton className="skeleton-heading" /><Skeleton className="skeleton-description" /></div><div className="page-skeleton-actions"><Skeleton className="skeleton-action" /><Skeleton className="skeleton-action skeleton-action-primary" /></div></div>
    <div className="page-skeleton-metrics">{Array.from({ length: 4 }, (_, index) => <div className="page-skeleton-metric" key={index}><Skeleton className="skeleton-label" /><Skeleton className="skeleton-number" /><Skeleton className="skeleton-caption" /></div>)}</div>
    <div className="page-skeleton-body"><div className="page-skeleton-panel page-skeleton-panel-wide"><Skeleton className="skeleton-panel-heading" /><Skeleton className="skeleton-chart" /></div><div className="page-skeleton-panel"><Skeleton className="skeleton-panel-heading" />{Array.from({ length: 5 }, (_, index) => <Skeleton className="skeleton-row" key={index} />)}</div></div>
    <span className="visually-hidden">Loading security workspace…</span>
  </div>
}
