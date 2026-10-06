import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import Papa from 'papaparse'
import jsPDF from 'jspdf'
import {
  Bar, BarChart, CartesianGrid, Cell, ComposedChart, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { toast } from 'sonner'
import {
  Activity, AlertOctagon, ArrowDownRight, ArrowUpRight, CalendarDays, Clock3,
  FileDown, FileSpreadsheet, ShieldCheck, Timer, TrendingUp,
} from 'lucide-react'
import { useAppStore } from '../store'
import { downloadText, formatTime, sanitizeCsvRows } from '../lib/utils'
import type { Alert, Incident } from '../types'
import { Button, EmptyState, PageHeader, SectionTitle } from '../components/Ui'

type ReportRange = '24h' | '7d' | '30d' | 'custom'
type TrendPoint = { label: string; start: number; end: number; alerts: number; critical: number }
type MttrPoint = { label: string; start: number; end: number; averageMinutes: number | null; resolved: number }

const DAY_MS = 24 * 60 * 60 * 1000
const palette = ['#06b6d4', '#10b981', '#f59e0b', '#f97316', '#a78bfa', '#ef4444', '#38bdf8', '#ec4899']
const rangeLabels: Record<Exclude<ReportRange, 'custom'>, string> = { '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days' }
const chartTooltipStyle = { background: '#111827', border: '1px solid #243247', borderRadius: 8, fontSize: 11, color: '#dce8f0' }

function localDayStart(value: string) {
  const [year, month, day] = value.split('-').map(Number)
  return new Date(year, month - 1, day, 0, 0, 0, 0).getTime()
}

function localDayEnd(value: string) {
  const [year, month, day] = value.split('-').map(Number)
  return new Date(year, month - 1, day, 23, 59, 59, 999).getTime()
}

function formatDateOnly(value: string) {
  const [year, month, day] = value.split('-').map(Number)
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(year, month - 1, day, 12))
}

function localDateInputValue(date = new Date()) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
}

function formatMinutes(value: number | null) {
  if (value === null || !Number.isFinite(value)) return '—'
  if (value >= 60) return `${Math.floor(value / 60)}h ${Math.round(value % 60)}m`
  return `${Math.round(value)} min`
}

function timestampOf(value: string | null | undefined) {
  if (!value) return NaN
  return new Date(value).getTime()
}

function alertInRange(alert: Alert, start: number, end: number) {
  const timestamp = timestampOf(alert.timestamp)
  return Number.isFinite(timestamp) && timestamp >= start && timestamp <= end
}

function resolvedIncidentInRange(incident: Incident, start: number, end: number) {
  if (incident.status !== 'resolved' || !incident.resolvedAt) return false
  const resolvedAt = timestampOf(incident.resolvedAt)
  return Number.isFinite(resolvedAt) && resolvedAt >= start && resolvedAt <= end
}

function mttrMinutes(incident: Incident) {
  const created = timestampOf(incident.createdAt)
  const resolved = timestampOf(incident.resolvedAt)
  if (!Number.isFinite(created) || !Number.isFinite(resolved) || resolved < created) return null
  return (resolved - created) / 60_000
}

function safePdfText(value: string) {
  return value.replace(/[^\x20-\x7E]/g, ' ').replace(/\s+/g, ' ').trim()
}

function ReportChartEmpty({ onOpenIncidents }: { onOpenIncidents: () => void }) {
  return <div className="report-chart-empty"><Clock3 size={21} /><span>No incidents were resolved in this period.</span><button onClick={onOpenIncidents}>Review incident workspace <ArrowUpRight size={12} /></button></div>
}

export default function ReportsPage() {
  const navigate = useNavigate()
  const alerts = useAppStore((state) => state.alerts)
  const incidents = useAppStore((state) => state.incidents)
  const [range, setRange] = useState<ReportRange>('24h')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const todayInputValue = localDateInputValue()

  const bounds = useMemo(() => {
    const now = Date.now()
    if (range !== 'custom') {
      const duration = range === '24h' ? DAY_MS : range === '7d' ? 7 * DAY_MS : 30 * DAY_MS
      return { start: now - duration, end: now }
    }
    let start = from ? localDayStart(from) : now - 30 * DAY_MS
    const end = to ? localDayEnd(to) : now
    if (!from && to) {
      const [year, month, day] = to.split('-').map(Number)
      start = new Date(year, month - 1, day - 29, 0, 0, 0, 0).getTime()
    }
    return { start, end }
  }, [range, from, to])
  const invalidDateRange = range === 'custom' && (Boolean(from && to && from > to) || bounds.start > bounds.end || bounds.start > Date.now())

  const rangeLabel = range === 'custom'
    ? `${from ? formatDateOnly(from) : '30 days before'} – ${to ? formatDateOnly(to) : 'Today'}`
    : rangeLabels[range]
  const periodToken = range === 'custom' ? `${from || 'last-30d'}-${to || 'today'}` : range

  const filtered = useMemo(() => {
    if (invalidDateRange) return []
    return alerts.filter((alert) => alertInRange(alert, bounds.start, bounds.end))
  }, [alerts, bounds, invalidDateRange])

  const bucketCount = useMemo(() => {
    const duration = Math.max(1, bounds.end - bounds.start)
    if (duration <= 36 * 60 * 60 * 1000) return 12
    if (duration <= 8 * DAY_MS) return 7
    return 15
  }, [bounds])

  const trend = useMemo<TrendPoint[]>(() => {
    if (invalidDateRange) return []
    const duration = Math.max(1, bounds.end - bounds.start)
    const step = duration / bucketCount
    const compact = duration <= 36 * 60 * 60 * 1000
    return Array.from({ length: bucketCount }, (_, index) => {
      const start = bounds.start + index * step
      const end = index === bucketCount - 1 ? bounds.end + 1 : bounds.start + (index + 1) * step
      const pointAlerts = filtered.filter((alert) => {
        const timestamp = timestampOf(alert.timestamp)
        return timestamp >= start && timestamp < end
      })
      const midpoint = new Date(start + (end - start) / 2)
      const label = compact
        ? midpoint.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
        : midpoint.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
      return { label, start, end, alerts: pointAlerts.length, critical: pointAlerts.filter((alert) => alert.severity === 'critical').length }
    })
  }, [filtered, bounds, bucketCount, invalidDateRange])

  const severityStats = useMemo(() => (['critical', 'high', 'medium', 'low'] as const).map((level) => ({
    name: level,
    value: filtered.filter((alert) => alert.severity === level).length,
  })), [filtered])

  const attackTypes = useMemo(() => {
    const counts = new Map<string, number>()
    filtered.forEach((alert) => counts.set(alert.attackType, (counts.get(alert.attackType) || 0) + 1))
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1])
    const top = sorted.slice(0, 5).map(([name, count], index) => ({ name, count, fill: palette[index] }))
    const otherCount = sorted.slice(5).reduce((total, [, count]) => total + count, 0)
    if (otherCount) top.push({ name: 'Other', count: otherCount, fill: palette[5] })
    return top
  }, [filtered])

  const attackers = useMemo(() => {
    const counts = new Map<string, { country: string; events: number }>()
    filtered.forEach((alert) => {
      const previous = counts.get(alert.sourceIp) || { country: alert.sourceCountry, events: 0 }
      previous.events += 1
      counts.set(alert.sourceIp, previous)
    })
    return [...counts.entries()].map(([ip, data]) => ({ ip, ...data })).sort((a, b) => b.events - a.events).slice(0, 8)
  }, [filtered])

  const resolvedIncidents = useMemo(() => invalidDateRange ? [] : incidents.filter((incident) => resolvedIncidentInRange(incident, bounds.start, bounds.end)), [incidents, bounds, invalidDateRange])
  const resolvedMttr = useMemo(() => resolvedIncidents.map(mttrMinutes).filter((value): value is number => value !== null), [resolvedIncidents])
  const averageMttr = resolvedMttr.length ? resolvedMttr.reduce((total, value) => total + value, 0) / resolvedMttr.length : null

  const mttrTrend = useMemo<MttrPoint[]>(() => trend.map((bucket) => {
    const bucketIncidents = resolvedIncidents.filter((incident) => {
      const resolved = timestampOf(incident.resolvedAt)
      return resolved >= bucket.start && resolved < bucket.end
    })
    const values = bucketIncidents.map(mttrMinutes).filter((value): value is number => value !== null)
    return {
      label: bucket.label,
      start: bucket.start,
      end: bucket.end,
      averageMinutes: values.length ? values.reduce((total, value) => total + value, 0) / values.length : null,
      resolved: values.length,
    }
  }), [trend, resolvedIncidents])

  const criticalCount = filtered.filter((alert) => alert.severity === 'critical').length
  const containedCount = filtered.filter((alert) => alert.status === 'resolved' || alert.status === 'blocked').length
  const containmentRate = filtered.length ? (containedCount / filtered.length) * 100 : 0

  const resetRange = () => {
    setRange('24h')
    setFrom('')
    setTo('')
  }
  const chooseRange = (nextRange: Exclude<ReportRange, 'custom'>) => {
    setRange(nextRange)
    setFrom('')
    setTo('')
  }

  const exportCSV = () => {
    if (invalidDateRange) return
    const rows = filtered.map((alert) => ({
      alert_id: alert.id,
      timestamp: alert.timestamp,
      severity: alert.severity,
      source_ip: alert.sourceIp,
      source_country: alert.sourceCountry,
      destination_ip: alert.destinationIp,
      protocol: alert.protocol,
      attack_type: alert.attackType,
      signature: alert.signature,
      status: alert.status,
    }))
    const fields = ['alert_id', 'timestamp', 'severity', 'source_ip', 'source_country', 'destination_ip', 'protocol', 'attack_type', 'signature', 'status']
    const csv = Papa.unparse({ fields, data: sanitizeCsvRows(rows) })
    downloadText(`netdefender-threat-report-${periodToken}.csv`, csv, 'text/csv;charset=utf-8')
    toast.success('CSV report exported', { description: `${filtered.length} alert records · ${rangeLabel}` })
  }

  const exportPDF = () => {
    if (invalidDateRange) return
    const pdf = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
    const pageWidth = 210
    const left = 18
    const right = 192
    const footer = (pageNumber: number) => {
      pdf.setDrawColor(42, 60, 75)
      pdf.line(left, 280, right, 280)
      pdf.setTextColor(94, 116, 134)
      pdf.setFont('helvetica', 'normal')
      pdf.setFontSize(7)
      pdf.text('CONFIDENTIAL · NETDEFENDER SECURITY OPERATIONS CENTER', left, 286)
      pdf.text(`Page ${pageNumber} of 2`, right, 286, { align: 'right' })
    }
    const header = (subtitle: string) => {
      pdf.setFillColor(10, 14, 26)
      pdf.rect(0, 0, pageWidth, 297, 'F')
      pdf.setFillColor(14, 29, 43)
      pdf.rect(0, 0, pageWidth, 47, 'F')
      pdf.setTextColor(6, 182, 212)
      pdf.setFont('helvetica', 'bold')
      pdf.setFontSize(19)
      pdf.text('NETDEFENDER', left, 21)
      pdf.setTextColor(222, 236, 244)
      pdf.setFont('helvetica', 'normal')
      pdf.setFontSize(8)
      pdf.text('SECURITY OPERATIONS · THREAT INTELLIGENCE REPORT', left, 29)
      pdf.setTextColor(160, 181, 196)
      pdf.setFontSize(9)
      pdf.text(safePdfText(subtitle), left, 39)
      pdf.setDrawColor(6, 182, 212)
      pdf.line(left, 47, right, 47)
    }

    header(`Reporting period: ${rangeLabel}   |   Generated: ${new Date().toLocaleString()}`)
    pdf.setTextColor(236, 245, 249)
    pdf.setFont('helvetica', 'bold')
    pdf.setFontSize(12)
    pdf.text('Executive summary', left, 59)
    const statCards = [
      { label: 'TOTAL DETECTIONS', value: String(filtered.length) },
      { label: 'CRITICAL EVENTS', value: String(criticalCount) },
      { label: 'MEAN MTTR', value: averageMttr === null ? 'N/A' : formatMinutes(averageMttr) },
      { label: 'CONTAINMENT', value: `${containmentRate.toFixed(1)}%` },
    ]
    const cardGap = 4
    const cardWidth = (right - left - cardGap * 3) / 4
    statCards.forEach((card, index) => {
      const x = left + index * (cardWidth + cardGap)
      pdf.setFillColor(18, 29, 43)
      pdf.setDrawColor(42, 60, 75)
      pdf.roundedRect(x, 65, cardWidth, 25, 2, 2, 'FD')
      pdf.setTextColor(123, 145, 162)
      pdf.setFont('helvetica', 'bold')
      pdf.setFontSize(6.5)
      pdf.text(card.label, x + 3, 72)
      pdf.setTextColor(230, 243, 248)
      pdf.setFont('helvetica', 'bold')
      pdf.setFontSize(12)
      pdf.text(safePdfText(card.value), x + 3, 84)
    })

    pdf.setTextColor(225, 239, 247)
    pdf.setFont('helvetica', 'bold')
    pdf.setFontSize(11)
    pdf.text('Detection trend', left, 101)
    pdf.setTextColor(118, 139, 156)
    pdf.setFont('helvetica', 'normal')
    pdf.setFontSize(7)
    pdf.text('Alerts by interval · critical detections shown as a line', left, 106)
    const plot = { x: 25, y: 113, width: 160, height: 43 }
    const trendMax = Math.max(1, ...trend.map((point) => point.alerts))
    const criticalMax = Math.max(1, ...trend.map((point) => point.critical))
    pdf.setDrawColor(41, 59, 73)
    ;[0, 0.5, 1].forEach((fraction) => {
      const y = plot.y + plot.height * fraction
      pdf.line(plot.x, y, plot.x + plot.width, y)
    })
    const slotWidth = plot.width / Math.max(1, trend.length)
    let previousCritical: { x: number; y: number } | null = null
    trend.forEach((point, index) => {
      const centerX = plot.x + slotWidth * (index + 0.5)
      const barHeight = (point.alerts / trendMax) * plot.height
      pdf.setFillColor(22, 103, 122)
      pdf.roundedRect(centerX - slotWidth * 0.23, plot.y + plot.height - barHeight, slotWidth * 0.46, Math.max(barHeight, 0.7), 0.7, 0.7, 'F')
      const criticalPoint = { x: centerX, y: plot.y + plot.height - (point.critical / criticalMax) * (plot.height * 0.78) - 2 }
      if (previousCritical) {
        pdf.setDrawColor(239, 68, 68)
        pdf.setLineWidth(0.55)
        pdf.line(previousCritical.x, previousCritical.y, criticalPoint.x, criticalPoint.y)
      }
      pdf.setFillColor(239, 93, 101)
      pdf.circle(criticalPoint.x, criticalPoint.y, 0.9, 'F')
      previousCritical = criticalPoint
      if (index % (trend.length > 10 ? 2 : 1) === 0) {
        pdf.setTextColor(105, 127, 145)
        pdf.setFont('helvetica', 'normal')
        pdf.setFontSize(5.5)
        pdf.text(safePdfText(point.label), centerX, plot.y + plot.height + 6, { align: 'center' })
      }
    })

    const drawRanked = (title: string, rows: Array<{ label: string; count: number }>, x: number, y: number, width: number, fill: [number, number, number]) => {
      pdf.setTextColor(225, 239, 247)
      pdf.setFont('helvetica', 'bold')
      pdf.setFontSize(10)
      pdf.text(title, x, y)
      const maxValue = Math.max(1, ...rows.map((row) => row.count))
      rows.slice(0, 5).forEach((row, index) => {
        const rowY = y + 10 + index * 11
        const label = safePdfText(row.label)
        const labelLines = pdf.splitTextToSize(label, width * 0.56) as string[]
        pdf.setTextColor(161, 181, 194)
        pdf.setFont('helvetica', 'normal')
        pdf.setFontSize(7)
        pdf.text(labelLines[0] || '', x, rowY)
        const barX = x + width * 0.59
        const barWidth = width * 0.27
        pdf.setFillColor(30, 47, 61)
        pdf.roundedRect(barX, rowY - 2.5, barWidth, 3, 1, 1, 'F')
        pdf.setFillColor(fill[0], fill[1], fill[2])
        pdf.roundedRect(barX, rowY - 2.5, Math.max(1, barWidth * row.count / maxValue), 3, 1, 1, 'F')
        pdf.setTextColor(216, 231, 239)
        pdf.setFont('helvetica', 'bold')
        pdf.text(String(row.count), x + width, rowY, { align: 'right' })
      })
    }
    const typeRows = attackTypes.map((item) => ({ label: item.name, count: item.count }))
    const attackerRows = attackers.slice(0, 5).map((item) => ({ label: `${item.ip} · ${item.country}`, count: item.events }))
    drawRanked('Top source addresses', attackerRows, left, 177, 82, [230, 85, 98])
    drawRanked('Attack types', typeRows, 110, 177, 82, [6, 182, 212])
    footer(1)

    pdf.addPage()
    header(`Response performance   |   ${rangeLabel}`)
    pdf.setTextColor(232, 242, 247)
    pdf.setFont('helvetica', 'bold')
    pdf.setFontSize(13)
    pdf.text('Mean time to resolve (MTTR)', left, 65)
    pdf.setTextColor(125, 147, 163)
    pdf.setFont('helvetica', 'normal')
    pdf.setFontSize(8)
    pdf.text(`${resolvedIncidents.length} incidents resolved in the selected period · Average ${averageMttr === null ? 'N/A' : formatMinutes(averageMttr)}`, left, 72)

    if (resolvedMttr.length) {
      const mttrPlot = { x: 28, y: 91, width: 154, height: 92 }
      const values = mttrTrend.filter((point) => point.averageMinutes !== null)
      const maxMinutes = Math.max(1, ...values.map((point) => point.averageMinutes || 0))
      pdf.setDrawColor(41, 59, 73)
      pdf.setLineWidth(0.2)
      ;[0, 0.5, 1].forEach((fraction) => {
        const y = mttrPlot.y + mttrPlot.height * fraction
        pdf.line(mttrPlot.x, y, mttrPlot.x + mttrPlot.width, y)
      })
      const slot = mttrPlot.width / Math.max(1, mttrTrend.length)
      let previous: { x: number; y: number } | null = null
      mttrTrend.forEach((point, index) => {
        if (point.averageMinutes === null) { previous = null; return }
        const location = {
          x: mttrPlot.x + slot * (index + 0.5),
          y: mttrPlot.y + mttrPlot.height - (point.averageMinutes / maxMinutes) * mttrPlot.height,
        }
        if (previous) {
          pdf.setDrawColor(245, 158, 11)
          pdf.setLineWidth(0.8)
          pdf.line(previous.x, previous.y, location.x, location.y)
        }
        pdf.setFillColor(245, 158, 11)
        pdf.circle(location.x, location.y, 1.4, 'F')
        previous = location
        if (index % (mttrTrend.length > 10 ? 2 : 1) === 0) {
          pdf.setTextColor(105, 127, 145)
          pdf.setFont('helvetica', 'normal')
          pdf.setFontSize(6)
          pdf.text(safePdfText(point.label), location.x, mttrPlot.y + mttrPlot.height + 9, { align: 'center' })
          pdf.setTextColor(203, 216, 225)
          pdf.setFontSize(6.5)
          pdf.text(`${Math.round(point.averageMinutes)}m`, location.x, location.y - 4, { align: 'center' })
        }
      })
    } else {
      pdf.setFillColor(17, 27, 40)
      pdf.setDrawColor(42, 60, 75)
      pdf.roundedRect(left, 90, right - left, 74, 3, 3, 'FD')
      pdf.setTextColor(122, 145, 161)
      pdf.setFont('helvetica', 'normal')
      pdf.setFontSize(10)
      pdf.text('No resolved incidents are available for the selected period.', pageWidth / 2, 130, { align: 'center' })
    }

    pdf.setTextColor(224, 238, 246)
    pdf.setFont('helvetica', 'bold')
    pdf.setFontSize(10)
    pdf.text('Response time by interval', left, 207)
    pdf.setTextColor(119, 141, 158)
    pdf.setFont('helvetica', 'normal')
    pdf.setFontSize(7)
    pdf.text('Bucket   |   Resolved incidents   |   Average minutes', left, 214)
    const populatedMttr = mttrTrend.filter((point) => point.averageMinutes !== null)
    populatedMttr.slice(0, 8).forEach((point, index) => {
      const y = 224 + index * 6
      pdf.setTextColor(163, 182, 196)
      pdf.text(safePdfText(point.label), left, y)
      pdf.text(String(point.resolved), 88, y)
      pdf.text(String(Math.round(point.averageMinutes || 0)), 125, y)
    })
    if (!populatedMttr.length) {
      pdf.setTextColor(124, 145, 161)
      pdf.text('No MTTR samples to display.', left, 224)
    }
    footer(2)
    pdf.save(`netdefender-threat-report-${periodToken}.pdf`)
    toast.success('PDF report generated', { description: rangeLabel })
  }

  return <div className="page reports-page">
    <PageHeader
      eyebrow="SECURITY INTELLIGENCE"
      title="Threat reports"
      description="Turn detection data into a clear picture of risk, activity, and response performance."
      actions={<><Button variant="secondary" onClick={exportCSV} disabled={invalidDateRange}><FileSpreadsheet size={15} /> Export CSV</Button><Button onClick={exportPDF} disabled={invalidDateRange}><FileDown size={15} /> Export PDF</Button></>}
    />

    <section className="report-filter-bar" aria-label="Report date range">
      <div className="report-range-label"><CalendarDays size={16} /><b>Reporting period</b><small>{rangeLabel}</small></div>
      <div className="segmented-control report-range-select" role="group" aria-label="Choose a preset reporting period">
        <button type="button" aria-pressed={range === '24h'} className={range === '24h' ? 'selected' : ''} onClick={() => chooseRange('24h')}>24 hours</button>
        <button type="button" aria-pressed={range === '7d'} className={range === '7d' ? 'selected' : ''} onClick={() => chooseRange('7d')}>7 days</button>
        <button type="button" aria-pressed={range === '30d'} className={range === '30d' ? 'selected' : ''} onClick={() => chooseRange('30d')}>30 days</button>
      </div>
      <div className={`report-custom-range ${range === 'custom' ? 'report-custom-range-active' : ''}`}>
        <label>From <input type="date" aria-label="Start date" value={from} max={to || todayInputValue} onChange={(event) => { setFrom(event.target.value); setRange('custom') }} /></label>
        <span className="report-range-dash">to</span>
        <label>To <input type="date" aria-label="End date" value={to} min={from || undefined} max={todayInputValue} onChange={(event) => { setTo(event.target.value); setRange('custom') }} /></label>
        {(range === 'custom' || from || to) && <button className="report-reset-range" type="button" onClick={resetRange}>Reset</button>}
      </div>
      <div className={`report-scope ${invalidDateRange ? 'report-scope-error' : ''}`}>
        <i className="pulse-dot" />
        {invalidDateRange ? 'Check date order' : `${filtered.length.toLocaleString()} events in scope`}
      </div>
    </section>

    <div className="report-stat-grid">
      <article className="report-stat-card"><div><span>Total detections</span><span className="report-icon report-icon-cyan"><Activity size={16} /></span></div><b>{filtered.length.toLocaleString()}</b><small className="report-stat-neutral">Across the selected period</small></article>
      <article className="report-stat-card"><div><span>Critical events</span><span className="report-icon report-icon-red"><AlertOctagon size={16} /></span></div><b>{criticalCount.toLocaleString()}</b><small className="report-stat-neutral">{filtered.length ? `${((criticalCount / filtered.length) * 100).toFixed(1)}% of detections` : 'No detections in range'}</small></article>
      <article className="report-stat-card"><div><span>Mean time to resolve</span><span className="report-icon report-icon-amber"><Timer size={16} /></span></div><b>{formatMinutes(averageMttr)}</b><small className="report-stat-neutral">{resolvedIncidents.length} resolved incident{resolvedIncidents.length === 1 ? '' : 's'}</small></article>
      <article className="report-stat-card"><div><span>Containment rate</span><span className="report-icon report-icon-green"><ShieldCheck size={16} /></span></div><b>{filtered.length ? `${containmentRate.toFixed(1)}%` : '—'}</b><small className="report-stat-neutral">{containedCount} resolved or blocked</small></article>
    </div>

    {invalidDateRange ? <section className="panel report-empty-panel"><EmptyState icon={<CalendarDays size={30} />} title="Date range needs attention" description="Choose a start date that is on or before the end date." action={<Button variant="secondary" onClick={resetRange}><ArrowDownRight size={14} /> Reset to last 24 hours</Button>} /></section> : filtered.length === 0 ? <section className="panel report-empty-panel"><EmptyState icon={<Activity size={30} />} title="No detections in this period" description="Expand the reporting window or review the alert queue to find telemetry for this report." action={<><Button variant="secondary" onClick={() => chooseRange('30d')}><CalendarDays size={14} /> View last 30 days</Button><Button onClick={() => navigate('/alerts')}><ArrowUpRight size={14} /> Review alerts</Button></>} /></section> : <div className="reports-grid">
      <section className="panel report-chart-panel report-trend">
        <SectionTitle title="Detection trend" subtitle={`Alert volume over time · ${bucketCount} intervals`} icon={<Activity size={16} />} />
        <div className="report-trend-chart"><ResponsiveContainer width="100%" height="100%"><ComposedChart data={trend} margin={{ top: 12, right: 12, left: -18, bottom: 0 }}>
          <CartesianGrid stroke="#1c2937" strokeDasharray="3 5" vertical={false} />
          <XAxis dataKey="label" axisLine={false} tickLine={false} tick={{ fill: '#718496', fontSize: 9 }} minTickGap={16} />
          <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#718496', fontSize: 9 }} />
          <Tooltip contentStyle={chartTooltipStyle} labelStyle={{ color: '#c6d6e0' }} />
          <Bar dataKey="alerts" name="Detections" fill="#164e63" radius={[4, 4, 0, 0]} barSize={13} />
          <Line dataKey="critical" name="Critical" stroke="#ef4444" strokeWidth={2} dot={{ r: 2, fill: '#ef4444' }} />
        </ComposedChart></ResponsiveContainer></div>
      </section>

      <section className="panel report-chart-panel report-attack">
        <SectionTitle title="Attack types" subtitle="Detection type distribution" icon={<ShieldCheck size={16} />} />
        <div className="report-attack-content"><div className="report-donut"><ResponsiveContainer width="100%" height="100%"><PieChart>
          <Pie data={attackTypes} dataKey="count" nameKey="name" cx="50%" cy="50%" innerRadius="57%" outerRadius="84%" stroke="none" paddingAngle={4}>{attackTypes.map((item) => <Cell key={item.name} fill={item.fill} />)}</Pie>
          <Tooltip contentStyle={chartTooltipStyle} />
        </PieChart></ResponsiveContainer><div className="report-donut-center"><b>{filtered.length}</b><span>TOTAL</span></div></div>
          <div className="report-attack-legend">{attackTypes.map((item) => <div key={item.name}><span><i style={{ background: item.fill }} />{item.name}</span><b>{item.count}</b></div>)}</div>
        </div>
      </section>

      <section className="panel report-chart-panel report-attackers">
        <SectionTitle title="Top source addresses" subtitle={`Top ${attackers.length} IPs by detection count`} icon={<ArrowUpRight size={16} />} />
        <div className="report-attacker-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={attackers} layout="vertical" margin={{ top: 7, right: 18, left: 2, bottom: 4 }}>
          <CartesianGrid stroke="#1c2937" strokeDasharray="3 5" horizontal={false} />
          <XAxis type="number" allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#718496', fontSize: 9 }} />
          <YAxis type="category" dataKey="ip" width={96} axisLine={false} tickLine={false} tick={{ fill: '#90a4b5', fontSize: 8, fontFamily: 'monospace' }} />
          <Tooltip contentStyle={chartTooltipStyle} formatter={(value) => [`${value} detections`, 'Volume']} labelFormatter={(label, payload) => payload?.[0]?.payload?.country ? `${label} · ${payload[0].payload.country}` : String(label)} />
          <Bar dataKey="events" name="Detections" fill="#ed5965" radius={[0, 4, 4, 0]} barSize={13} />
        </BarChart></ResponsiveContainer></div>
      </section>

      <section className="panel report-chart-panel report-mttr">
        <SectionTitle title="MTTR trend" subtitle="Average resolution time for incidents resolved in each interval" icon={<Timer size={16} />} />
        {resolvedMttr.length === 0 ? <ReportChartEmpty onOpenIncidents={() => navigate('/incidents')} /> : <div className="report-mttr-chart"><ResponsiveContainer width="100%" height="100%"><LineChart data={mttrTrend} margin={{ top: 13, right: 13, left: -13, bottom: 0 }}>
          <CartesianGrid stroke="#1c2937" strokeDasharray="3 5" vertical={false} />
          <XAxis dataKey="label" axisLine={false} tickLine={false} tick={{ fill: '#718496', fontSize: 9 }} minTickGap={16} />
          <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#718496', fontSize: 9 }} unit="m" />
          <Tooltip contentStyle={chartTooltipStyle} labelStyle={{ color: '#c6d6e0' }} formatter={(value, _name, item) => [`${formatMinutes(Number(value))} · ${item.payload.resolved} incident${item.payload.resolved === 1 ? '' : 's'}`, 'MTTR']} />
          <Line type="monotone" dataKey="averageMinutes" name="MTTR" connectNulls stroke="#f59e0b" strokeWidth={2.5} dot={{ r: 3, fill: '#f59e0b', stroke: '#131c29', strokeWidth: 2 }} activeDot={{ r: 5 }} />
        </LineChart></ResponsiveContainer></div>}
      </section>

      <section className="panel report-chart-panel report-severity">
        <SectionTitle title="Severity breakdown" subtitle="Current reporting period" icon={<ShieldCheck size={16} />} />
        <div className="severity-report-list">{severityStats.map((item) => <div key={item.name} className={`severity-report-row severity-report-${item.name}`}><span><i />{item.name}</span><div className="severity-report-bar"><i style={{ width: `${filtered.length ? (item.value / filtered.length) * 100 : 0}%` }} /></div><b>{item.value}</b><small>{filtered.length ? Math.round(item.value / filtered.length * 100) : 0}%</small></div>)}</div>
        <div className="severity-report-footer"><TrendingUp size={14} /> {containedCount} of {filtered.length} alerts contained</div>
      </section>
    </div>}

    <div className="report-disclaimer"><ShieldCheck size={14} /><span>Report metrics are calculated from telemetry and incident records in the selected date range.</span><span>Generated {formatTime(new Date(), true)}</span></div>
  </div>
}
