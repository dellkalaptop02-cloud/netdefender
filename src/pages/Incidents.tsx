import { useState } from 'react'
import { DndContext, PointerSensor, closestCorners, useDraggable, useDroppable, useSensor, useSensors, type DragEndEvent } from '@dnd-kit/core'
import { CSS } from '@dnd-kit/utilities'
import { z } from 'zod'
import { toast } from 'sonner'
import { Activity, CalendarClock, Check, ChevronDown, CirclePlus, Clock3, GripVertical, Plus, Send, Siren, UserRound } from 'lucide-react'
import { useAppStore } from '../store'
import { formatTime, timeAgo } from '../lib/utils'
import type { Incident, IncidentStatus } from '../types'
import { Avatar, Button, EmptyState, Modal, PageHeader, SeverityBadge, StatusBadge } from '../components/Ui'

const columns: { id: IncidentStatus; title: string; eyebrow: string; color: string }[] = [
  { id: 'new', title: 'New', eyebrow: 'AWAITING TRIAGE', color: 'column-cyan' },
  { id: 'investigating', title: 'Investigating', eyebrow: 'ACTIVE RESPONSE', color: 'column-amber' },
  { id: 'resolved', title: 'Resolved', eyebrow: 'CLOSED CASES', color: 'column-green' },
]

function IncidentCard({ incident, onOpen, canUpdate }: { incident: Incident; onOpen: (incident: Incident) => void; canUpdate: boolean }) {
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({ id: incident.id, disabled: !canUpdate })
  return <article ref={setNodeRef} style={{ transform: CSS.Translate.toString(transform), opacity: isDragging ? 0.42 : 1 }} className="incident-card" onClick={() => onOpen(incident)}>
    <div className="incident-card-top"><span className="incident-id">{incident.id}</span>{canUpdate && <button className="drag-handle" aria-label="Drag incident" {...listeners} {...attributes} onClick={(event) => event.stopPropagation()}><GripVertical size={15} /></button>}</div>
    <h3>{incident.title}</h3><p>{incident.description}</p>
    <div className="incident-card-tags"><SeverityBadge severity={incident.severity} />{incident.status === 'resolved' && <span className="resolved-time"><Check size={12} /> Closed</span>}</div>
    <div className="incident-card-footer"><div className="incident-assignee"><Avatar name={incident.assignedTo} size="sm" /><span>{incident.assignedTo.split(' ')[0]}</span></div><span className="incident-created"><Clock3 size={12} />{timeAgo(incident.createdAt)}</span><span className="incident-comments"><Activity size={13} />{incident.notes.length}</span></div>
  </article>
}

function IncidentColumn({ column, incidents, onOpen, canUpdate }: { column: typeof columns[number]; incidents: Incident[]; onOpen: (incident: Incident) => void; canUpdate: boolean }) {
  const { isOver, setNodeRef } = useDroppable({ id: column.id })
  return <section ref={setNodeRef} className={`kanban-column ${column.color} ${isOver ? 'column-drop-target' : ''}`}>
    <header className="kanban-column-header"><div><span className="column-color-dot" /><h2>{column.title}</h2><span className="column-count">{incidents.length}</span></div><small>{column.eyebrow}</small></header>
    <div className="kanban-card-list">{incidents.map((incident) => <IncidentCard key={incident.id} incident={incident} onOpen={onOpen} canUpdate={canUpdate} />)}{incidents.length === 0 && <div className="kanban-empty">Drop incidents here</div>}</div>
  </section>
}

const createIncidentSchema = z.object({ title: z.string().min(5, 'Title must be at least 5 characters'), description: z.string().min(10, 'Add a short incident summary'), severity: z.enum(['low', 'medium', 'high', 'critical']) })

export default function IncidentsPage() {
  const incidents = useAppStore((state) => state.incidents)
  const addIncident = useAppStore((state) => state.addIncident)
  const moveIncident = useAppStore((state) => state.moveIncident)
  const addIncidentNote = useAppStore((state) => state.addIncidentNote)
  const user = useAppStore((state) => state.user)
  const [selected, setSelected] = useState<Incident | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [note, setNote] = useState('')
  const [newIncident, setNewIncident] = useState({ title: '', description: '', severity: 'medium' as Incident['severity'] })
  const [errors, setErrors] = useState<Record<string, string>>({})
  const canUpdate = user?.role === 'admin' || user?.role === 'analyst'
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 5 } }))
  const onDragEnd = (event: DragEndEvent) => {
    if (!canUpdate || !event.over) return
    const target = String(event.over.id)
    if (!columns.some((column) => column.id === target)) return
    const incident = incidents.find((item) => item.id === String(event.active.id))
    if (incident && incident.status !== target) { moveIncident(incident.id, target as IncidentStatus); toast.success(`${incident.id} moved to ${target}`) }
  }
  const create = () => {
    if (user?.role !== 'admin') return
    const parsed = createIncidentSchema.safeParse(newIncident)
    if (!parsed.success) { setErrors(Object.fromEntries(parsed.error.issues.map((issue) => [String(issue.path[0]), issue.message]))); return }
    const item: Incident = { id: `INC-${Date.now().toString().slice(-4)}`, title: parsed.data.title, description: parsed.data.description, severity: parsed.data.severity, status: 'new', assignedTo: user?.fullName || 'Alex Morgan', createdAt: new Date().toISOString(), notes: [] }
    addIncident(item); setCreateOpen(false); setNewIncident({ title: '', description: '', severity: 'medium' }); setErrors({}); toast.success('Incident created and added to triage')
  }
  const addNote = () => { if (!canUpdate || !selected || note.trim().length < 2) return; addIncidentNote(selected.id, note.trim()); setSelected({ ...selected, notes: [...selected.notes, note.trim()] }); setNote(''); toast.success('Investigation note added') }
  const setStatus = (status: IncidentStatus) => { if (!canUpdate || !selected) return; moveIncident(selected.id, status); setSelected({ ...selected, status, resolvedAt: status === 'resolved' ? new Date().toISOString() : null }); toast.success(`Incident status updated to ${status}`) }

  return <div className="page incidents-page">
    <PageHeader eyebrow="INCIDENT RESPONSE" title="Incident workspace" description="Coordinate investigations from first signal to resolution. Drag cards to update their status." actions={<><span className="board-total"><Siren size={15} /> {incidents.length} open cases</span>{user?.role === 'admin' && <Button onClick={() => setCreateOpen(true)}><Plus size={16} /> New incident</Button>}</>} />
    {incidents.length === 0 ? <section className="panel incident-empty-panel"><EmptyState icon={<Siren size={30} />} title="No incidents in the workspace" description="Create a case to coordinate triage, ownership, and investigation notes from first signal to resolution." action={user?.role === 'admin' ? <Button onClick={() => setCreateOpen(true)}><Plus size={15} /> Create first incident</Button> : undefined} /></section> : <>
      <div className="kanban-toolbar"><div className="board-view-switch"><span className="view-switch-active"><Activity size={14} /> Board</span><span><CalendarClock size={14} /> Timeline</span></div><div className="board-legend"><span><i className="legend-critical" /> Critical</span><span><i className="legend-high" /> High</span><span><i className="legend-medium" /> Medium</span>{canUpdate && <span className="drag-help"><GripVertical size={13} /> Drag to move</span>}</div></div>
      <DndContext sensors={sensors} collisionDetection={closestCorners} onDragEnd={onDragEnd}><div className="kanban-board">{columns.map((column) => <IncidentColumn key={column.id} column={column} incidents={incidents.filter((incident) => incident.status === column.id)} onOpen={setSelected} canUpdate={canUpdate} />)}</div></DndContext>
      <div className="kanban-footer"><span><Activity size={14} /> Changes sync live across your SOC workspace</span><span><i className="pulse-dot" /> Board updated just now</span></div>
    </>}

    <Modal open={!!selected} onClose={() => { setSelected(null); setNote('') }} title={selected?.title || 'Incident'} subtitle={selected ? `${selected.id} · opened ${formatTime(selected.createdAt, true)}` : ''} size="lg" footer={selected && <><Button variant="ghost" onClick={() => setSelected(null)}>Close</Button>{canUpdate && <Button variant={selected.status === 'resolved' ? 'secondary' : 'primary'} onClick={() => setStatus(selected.status === 'resolved' ? 'investigating' : 'resolved')}>{selected.status === 'resolved' ? <Activity size={15} /> : <Check size={15} />}{selected.status === 'resolved' ? 'Reopen incident' : 'Mark resolved'}</Button>}</>}>
      {selected && <div className="incident-detail"><div className="incident-detail-top"><SeverityBadge severity={selected.severity} /><StatusBadge status={selected.status} /><div className="incident-assign"><Avatar name={selected.assignedTo} size="sm" /><span><small>Assigned to</small><b>{selected.assignedTo}</b></span>{canUpdate && <button title="Assign to me" onClick={() => { setSelected({ ...selected, assignedTo: user?.fullName || 'Alex Morgan' }); toast.success('Incident assigned to you') }}><UserRound size={14} /></button>}</div></div><p className="incident-full-description">{selected.description}</p><label className="form-field incident-status-select"><span>Workflow status</span><div className="select-input"><select value={selected.status} disabled={!canUpdate} onChange={(event) => setStatus(event.target.value as IncidentStatus)}><option value="new">New</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select><ChevronDown size={14} /></div></label>
        <div className="incident-timeline-section"><h3><Activity size={15} /> Investigation timeline</h3><div className="incident-timeline-item"><span className="timeline-bullet timeline-bullet-cyan" /><div><b>Incident created</b><p>Automatically surfaced by detection correlation.</p><time>{formatTime(selected.createdAt, true)}</time></div></div>{selected.status !== 'new' && <div className="incident-timeline-item"><span className="timeline-bullet timeline-bullet-amber" /><div><b>Status changed to {selected.status}</b><p>Updated by {user?.fullName || 'Alex Morgan'}.</p><time>{formatTime(selected.resolvedAt || selected.createdAt, true)}</time></div></div>}{selected.notes.map((item, index) => <div className="incident-timeline-item" key={`${item}-${index}`}><span className="timeline-bullet timeline-bullet-green" /><div><b>Investigation note · {user?.fullName || 'SOC analyst'}</b><p>{item}</p><time>{formatTime(selected.createdAt, true)}</time></div></div>)}</div>
        <div className="incident-note-box"><textarea value={note} disabled={!canUpdate} onChange={(event) => setNote(event.target.value)} placeholder={canUpdate ? 'Add an investigation note...' : 'Read-only incident access'} /><button onClick={addNote} disabled={!canUpdate || note.trim().length < 2}><Send size={14} /> Add note</button></div>
      </div>}
    </Modal>

    <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Create incident" subtitle="Open a case in the SOC response workspace." size="md" footer={<><Button variant="ghost" onClick={() => setCreateOpen(false)}>Cancel</Button><Button onClick={create}><CirclePlus size={15} /> Create incident</Button></>}>
      <div className="form-stack"><label className="form-field"><span>Incident title <b>*</b></span><input value={newIncident.title} onChange={(event) => setNewIncident({ ...newIncident, title: event.target.value })} placeholder="e.g. Suspicious outbound traffic" />{errors.title && <small className="field-error">{errors.title}</small>}</label><label className="form-field"><span>Summary <b>*</b></span><textarea className="form-textarea" value={newIncident.description} onChange={(event) => setNewIncident({ ...newIncident, description: event.target.value })} placeholder="Describe the investigation context..." />{errors.description && <small className="field-error">{errors.description}</small>}</label><label className="form-field"><span>Severity</span><div className="select-input"><select value={newIncident.severity} onChange={(event) => setNewIncident({ ...newIncident, severity: event.target.value as Incident['severity'] })}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><ChevronDown size={14} /></div></label></div>
    </Modal>
  </div>
}
