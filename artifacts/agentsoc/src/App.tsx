import { type ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Link, Route, Switch, useLocation, useParams, Router as WouterRouter } from 'wouter';
import {
  Activity, AlertCircle, AlertTriangle, ArrowDown, ArrowLeft, ArrowUp, BarChart3,
  Bell, Bot, Check, CheckCircle2, ChevronRight, CircleDot, Cloud,
  Code2, Cpu, Database, Download, ExternalLink, FileSearch, Filter, Fingerprint, GitBranch,
  History, KeyRound, LayoutDashboard, LockKeyhole, Menu,
  Play, RefreshCw, Search, Server, ShieldAlert, ShieldCheck, SlidersHorizontal,
  Terminal, X, Zap
} from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts';
import {
  type Agent, type Approval, type AuditEntry, type Incident, type SecurityEvent, type TriageInfo, type InvestigationInfo, type ComplianceInfo, type RemediationInfo, type VerificationInfo, type MLPredictionInfo,
  seedAudit
} from '@/data';
import {
  type CloudState, type DashboardData, type DashboardStats, type DataMode, type ComplianceRunSummary, type RemediationRunSummary, type VerificationRunSummary, type InvestigationRunSummary, type MonitorRunSummary, type ScenarioResult, type TriageRunSummary,
  type LearningRecordInfo, type LearningStats, type MlMetrics, type MlStatus,
  getLearning, getLearningStats, getMlMetrics, getMlStatus, requestRetry, runFeedback, submitFeedback,
  demoData, loadDashboard, decideApproval, resetEnvironment, runCompliance, runInvestigation, runRemediation, runVerification, runMonitor, runScenario, runTriage
} from '@/lib/api';
import { LoadingScreen } from '@/components/LoadingScreen';

const queryClient = new QueryClient();

function Badge({ children, kind = '' }: { children: ReactNode; kind?: string }) {
  return <span className={`badge ${kind}`} data-testid={`badge-${String(children).replace(/\s/g, '-').toLowerCase()}`}>{children}</span>;
}

function Panel({ title, meta, actions, children, className = '' }: { title?: string; meta?: string; actions?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}>
    {(title || actions) && <div className="panel-header"><div className="panel-title">{title}{meta && <small>{meta}</small>}</div>{actions}</div>}
    {children}
  </section>;
}

function PageHead({ eyebrow, title, subtitle, actions }: { eyebrow: string; title: string; subtitle?: string; actions?: ReactNode }) {
  return <div className="page-head">
    <div><div className="eyebrow">{eyebrow}</div><h1 className="page-title">{title}</h1>{subtitle && <p className="page-subtitle">{subtitle}</p>}</div>
    {actions && <div>{actions}</div>}
  </div>;
}

function StatCard({ label, value, meta, icon: Icon, accent = '' }: { label: string; value: string; meta: string; icon: typeof Activity; accent?: string }) {
  return <div className="panel stat-card"><div className={`accent-line ${accent}`} /><span className="stat-label">{label}</span><div className="stat-value">{value}</div><span className="stat-meta">{meta}</span><Icon className="stat-icon" size={18} /></div>;
}

function Toast({ toast, onClose }: { toast: { title: string; message: string } | null; onClose: () => void }) {
  if (!toast) return null;
  return <div className="toast" role="status" data-testid="toast-feedback"><CheckCircle2 size={17} /><div><strong>{toast.title}</strong><span>{toast.message}</span></div><button className="button ghost" style={{ minHeight: 22, padding: '0 4px', marginLeft: 'auto' }} onClick={onClose} aria-label="Close notification" data-testid="button-close-toast"><X size={13} /></button></div>;
}

function ConfirmModal({ title, body, confirmLabel, danger, onCancel, onConfirm }: { title: string; body: ReactNode; confirmLabel: string; danger?: boolean; onCancel: () => void; onConfirm: () => void }) {
  return <div className="modal-backdrop" role="dialog" aria-modal="true"><div className="modal">
    <div className="modal-head"><strong>{title}</strong><button className="button ghost" onClick={onCancel} aria-label="Close dialog" data-testid="button-close-dialog"><X size={15} /></button></div>
    <div className="modal-body">{body}</div>
    <div className="modal-actions"><button className="button ghost" onClick={onCancel} data-testid="button-cancel-confirmation">Cancel</button><button className={`button ${danger ? 'danger' : 'primary'}`} onClick={onConfirm} data-testid="button-confirm-action">{confirmLabel}</button></div>
  </div></div>;
}

const nav = [
  { href: '/', label: 'SOC Overview', icon: LayoutDashboard },
  { href: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { href: '/events', label: 'Security Events', icon: Activity },
  { href: '/agents', label: 'Agent Network', icon: Bot },
  { href: '/approvals', label: 'Approval Center', icon: CheckCircle2 },
];
const operations = [
  { href: '/cloud', label: 'Cloud Environment', icon: Cloud },
  { href: '/simulator', label: 'Attack Simulator', icon: Terminal },
  { href: '/analytics', label: 'Analytics', icon: BarChart3 },
  { href: '/audit', label: 'Audit Log', icon: History },
];

function Sidebar({ open, onClose, pendingApprovals }: { open: boolean; onClose: () => void; pendingApprovals: number }) {
  const [location] = useLocation();
  return <aside className={`sidebar ${open ? 'open' : ''}`}>
    <div style={{ padding: '20px 18px 16px', display: 'flex', alignItems: 'center', gap: 10 }}><div className="brand-mark">A</div><div><div className="brand-copy">AgentSOC</div><div className="eyebrow" style={{ marginTop: 2, fontSize: 8 }}>AUTONOMOUS DEFENSE</div></div><button className="button ghost" style={{ display: 'none', marginLeft: 'auto' }} onClick={onClose}><X size={15} /></button></div>
    <div className="nav-label">Command center</div>
    {nav.map(({ href, label, icon: Icon }) => <Link key={href} href={href} className={`nav-item ${location === href ? 'active' : ''}`} onClick={onClose} data-testid={`link-nav-${label.toLowerCase().replace(/\s/g, '-')}`}><Icon /><span>{label}</span>{label === 'Approval Center' && <span style={{ marginLeft: 'auto', color: 'hsl(var(--primary))', fontFamily: 'var(--app-font-mono)', fontSize: 10 }}>{String(pendingApprovals).padStart(2, '0')}</span>}</Link>)}
    <div className="nav-label">Operations</div>
    {operations.map(({ href, label, icon: Icon }) => <Link key={href} href={href} className={`nav-item ${location === href ? 'active' : ''}`} onClick={onClose} data-testid={`link-nav-${label.toLowerCase().replace(/\s/g, '-')}`}><Icon /><span>{label}</span></Link>)}
    <div className="sidebar-footer"><div className="profile-chip"><div className="avatar">AS</div><div style={{ flex: 1 }}><div className="strong" style={{ fontSize: 11 }}>A. Sharma</div><div className="mono muted">Lead analyst</div></div><CircleDot size={12} color="hsl(var(--secondary))" /></div><div className="mono muted" style={{ marginTop: 12, display: 'flex', justifyContent: 'space-between' }}><span>SIM ENV / AWS</span><span>v0.8.4</span></div></div>
  </aside>;
}

function Shell({ children, onRefresh, refreshTick, mode, pendingApprovals }: { children: ReactNode; onRefresh: () => void; refreshTick: number; mode: DataMode; pendingApprovals: number }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  return <div className="app-shell"><Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} pendingApprovals={pendingApprovals} /><div className="main-area">
    <header className="topbar"><div style={{ display: 'flex', alignItems: 'center', gap: 12 }}><button className="mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Open navigation" data-testid="button-open-navigation"><Menu size={16} /></button><div className="eyebrow">SECURITY OPERATIONS / {new Date().toISOString().slice(0, 10)}</div></div><div className="topbar-right"><div className="sync-pill" data-testid="status-data-mode" title={mode === 'live' ? 'Data from the AgentSOC backend' : 'Backend unreachable: showing bundled demo data'}><span className="pulse-dot" />{mode === 'live' ? 'LIVE BACKEND' : 'DEMO DATA'} <span className="mono" style={{ color: '#b8b5c4' }}>#{String(refreshTick).padStart(3, '0')}</span></div><button className="button ghost" onClick={onRefresh} data-testid="button-refresh-data"><RefreshCw size={14} />Refresh</button><button className="button ghost" aria-label="Notifications" data-testid="button-notifications"><Bell size={15} /></button></div></header>
    <main className="content">{children}</main>
  </div></div>;
}

function Overview({ incidents, agents, stats, mode, goSimulator }: { incidents: Incident[]; agents: Agent[]; stats: DashboardStats; mode: DataMode; goSimulator: () => void }) {
  const live = mode === 'live';
  const pad = (value: number) => String(value).padStart(2, '0');
  const risk = (['critical', 'high', 'medium', 'low'] as const).map(level => incidents.filter(i => i.severity === level && i.status !== 'Resolved').length);
  const chartData = [{ time:'08:00', critical:1, total:13 }, { time:'10:00', critical:2, total:21 }, { time:'12:00', critical:1, total:17 }, { time:'14:00', critical:4, total:36 }, { time:'16:00', critical:2, total:24 }, { time:'18:00', critical:3, total:29 }];
  return <><PageHead eyebrow="Live posture / simulated AWS" title="SOC Overview" subtitle="A high-confidence view of detections, autonomous reasoning, and controlled response." actions={<button className="button primary" onClick={goSimulator} data-testid="button-run-attack-simulation"><Play size={14} />Run attack simulation</button>} />
    <div className="grid-4"><StatCard label="Open incidents" value={String(incidents.filter(i => i.status !== 'Resolved').length).padStart(2, '0')} meta={live ? 'From incident store' : '↑ 2 since 12:00'} icon={ShieldAlert} /><StatCard label={live ? 'Events today' : 'Events / 24h'} value={stats.eventsToday.toLocaleString()} meta={live ? `${stats.totalEvents.toLocaleString()} stored in total` : '↑ 18.6% vs baseline'} icon={Activity} accent="cyan" /><StatCard label="Agent confidence" value={live ? (incidents.length ? `${Math.round(incidents.reduce((sum, i) => sum + i.confidence, 0) / incidents.length)}%` : '—') : '94.7%'} meta={live ? 'Monitor Agent · incident confidence' : 'Across active cases'} icon={Bot} accent="lime" /><StatCard label="Awaiting approval" value={pad(stats.pendingApprovals)} meta="Human gate required" icon={LockKeyhole} accent="amber" /></div>
    <div className="overview-grid"><Panel title="Threat activity" meta="LAST 12 HOURS" actions={<div className="legend-row"><span className="legend-item"><span className="legend-swatch" style={{ background: 'hsl(var(--primary))' }} />Total signals</span><span className="legend-item"><span className="legend-swatch" style={{ background: 'hsl(var(--secondary))' }} />Critical</span></div>}><div className="activity-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData} margin={{ top: 8, right: 8, left: -25, bottom: 0 }}><defs><linearGradient id="totalFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#ec49ab" stopOpacity=".32" /><stop offset="1" stopColor="#ec49ab" stopOpacity="0" /></linearGradient></defs><CartesianGrid stroke="#282633" vertical={false} /><XAxis dataKey="time" tick={{ fill: '#777586', fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis tick={{ fill: '#777586', fontSize: 10 }} axisLine={false} tickLine={false} /><ChartTooltip contentStyle={{ background: '#191824', border: '1px solid #4a3850', fontSize: 11 }} /><Area type="monotone" dataKey="total" stroke="#ec49ab" fill="url(#totalFill)" strokeWidth={2} /><Area type="monotone" dataKey="critical" stroke="#c9f237" fill="none" strokeWidth={2} /></AreaChart></ResponsiveContainer></div></Panel>
      <Panel title="Risk distribution" meta="OPEN FINDINGS"><div className="panel-body"><div className="bar-list">{[['Critical', risk[0], 'hsl(var(--destructive))'], ['High', risk[1], '#ef9b5c'], ['Medium', risk[2], '#e7cf63'], ['Low', risk[3], '#69d0a4']].map(([label, value, color]) => <div className="bar-row" key={label as string}><span>{label}</span><div className="bar-track"><div className="bar-fill" style={{ width: `${Number(value) * 33 + 5}%`, background: color as string }} /></div><span className="bar-value">{String(value).padStart(2, '0')}</span></div>)}</div><div style={{ borderTop: '1px solid #292634', marginTop: 22, paddingTop: 16 }}><div className="eyebrow">Environment posture</div><div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 8 }}><span className="stat-value" style={{ fontSize: 25 }}>87<span style={{ fontSize: 14, color: '#858391' }}>/100</span></span><Badge kind="active">stable</Badge></div></div></div></Panel></div>
    <div className="overview-grid"><Panel title="Active agent pipeline" meta={`${agents.length} SPECIALISTS / ${agents.filter(a => a.status === 'Active').length} RUNNING`}><div className="pipeline">{agents.map((agent, i) => { const done = !live && i < 3; return <div className="pipeline-step" key={agent.id}><div className={`pipeline-node ${done ? 'done' : !live && i === 3 ? 'current' : ''}`}>{done ? <Check size={15} /> : <Bot size={15} />}</div><div className="pipeline-label">{agent.name.replace(' Agent', '')}</div><div className="pipeline-detail">{done ? 'completed' : live ? agent.lastActivity : agent.status.toLowerCase()}</div></div>; })}</div></Panel>
      <Panel title="Top detections" meta="BY CONFIDENCE"><div className="threat-list" style={{ padding: '0 16px' }}>{incidents.slice(0, 3).map(item => <Link href={`/incidents/${item.id}`} className="threat-row" key={item.id} data-testid={`link-detection-${item.id}`}><div><div className="strong" style={{ fontSize: 11 }}>{item.title}</div><p>{item.id} · {item.source}</p></div><div className="threat-score">{item.confidence}%</div></Link>)}</div></Panel></div>
    <div style={{ marginTop: 14 }}><Panel title="Recent incidents" meta="LATEST SIGNALS" actions={<Link href="/incidents" className="button ghost" data-testid="link-view-all-incidents">View all <ChevronRight size={13} /></Link>}><IncidentTable incidents={incidents.slice(0, 4)} /></Panel></div>
  </>;
}

function IncidentTable({ incidents }: { incidents: Incident[] }) {
  const [, setLocation] = useLocation();
  return <div className="table-wrap"><table className="data-table"><thead><tr><th>Incident</th><th>Severity</th><th>Source</th><th>Resource / user</th><th>Agent</th><th>Status</th><th>Confidence</th></tr></thead><tbody>{incidents.map(item => <tr key={item.id} className="row-link" tabIndex={0} role="link" onClick={() => setLocation(`/incidents/${item.id}`)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') setLocation(`/incidents/${item.id}`); }} data-testid={`row-incident-${item.id}`}><td><div className="mono" style={{ color: 'hsl(var(--primary))' }}>{item.id}</div><div className="strong" style={{ marginTop: 4 }}>{item.title}</div><div className="mono muted" style={{ marginTop: 4 }}>{item.created}</div></td><td><Badge kind={item.severity}>{item.severity}</Badge></td><td>{item.source}</td><td><div className="strong">{item.resource.split('/').pop()}</div><div className="mono muted">{item.user}</div></td><td><span className="mono">{item.currentAgent}</span></td><td><Badge kind={item.status === 'Awaiting approval' ? 'review' : item.status === 'Contained' || item.status === 'Triaged' || item.status === 'Investigated' || item.status === 'Compliance assessed' || item.status.startsWith('Remediat') || item.status.startsWith('Verif') || item.status === 'Partial remediation' ? 'active' : ''}>{item.status}</Badge></td><td><span className="mono">{item.confidence}%</span></td></tr>)}</tbody></table></div>;
}

function IncidentsPage({ incidents }: { incidents: Incident[] }) {
  const [query, setQuery] = useState(''); const [severity, setSeverity] = useState('all'); const [status, setStatus] = useState('all');
  const filtered = useMemo(() => incidents.filter(item => (`${item.id} ${item.title} ${item.source} ${item.user}`.toLowerCase().includes(query.toLowerCase()) && (severity === 'all' || item.severity === severity) && (status === 'all' || item.status === status))), [incidents, query, severity, status]);
  return <><PageHead eyebrow={`Case management / ${String(incidents.length).padStart(2, '0')} records`} title="Incidents" subtitle="Search, prioritize, and trace every detection through the response pipeline." actions={<button className="button ghost" onClick={() => { setQuery(''); setSeverity('all'); setStatus('all'); }} data-testid="button-clear-incident-filters"><SlidersHorizontal size={14} />Reset filters</button>} />
    <Panel title="Incident queue" meta={`${filtered.length} MATCHING RECORDS`}><div className="filters"><div style={{ position: 'relative' }}><Search size={14} style={{ position: 'absolute', left: 10, top: 10, color: '#706e7e' }} /><input className="field search-field" style={{ paddingLeft: 31 }} placeholder="Search incident, user, source..." value={query} onChange={e => setQuery(e.target.value)} data-testid="input-search-incidents" /></div><select className="field select-field" value={severity} onChange={e => setSeverity(e.target.value)} data-testid="select-incident-severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select className="field select-field" value={status} onChange={e => setStatus(e.target.value)} data-testid="select-incident-status"><option value="all">All statuses</option><option>New</option><option>Triaged</option><option>Investigated</option><option>Compliance assessed</option><option>Remediation pending</option><option>Remediation approved</option><option>Remediation rejected</option><option>Remediation failed</option><option>Remediated</option><option>Verified</option><option>Verification failed</option><option>Partial remediation</option><option>Verification unknown</option><option>Investigating</option><option>Awaiting approval</option><option>Contained</option><option>Resolved</option></select><span className="eyebrow" style={{ marginLeft: 'auto', alignSelf: 'center' }}><Filter size={12} style={{ verticalAlign: 'middle', marginRight: 5 }} />Live filter</span></div>{filtered.length ? <IncidentTable incidents={filtered} /> : <div className="empty-state"><Search size={24} /><strong>No incidents match those filters</strong><span>Try widening the search or severity scope.</span></div>}</Panel></>;
}

const OUTCOME_TEXT: Record<string, string> = {
  llm_unavailable: 'The LLM is not reachable (is Ollama running?). The incident was not changed.',
  llm_not_configured: 'No LLM provider is configured (LLM_PROVIDER=none). The incident was not changed.',
  llm_error: 'The LLM returned an error. The incident was not changed.',
  invalid_llm_output: 'The model output failed validation (after one repair attempt). The incident was not changed.',
  policy_violation: 'The model decision broke a triage policy rule and was rejected. The incident was not changed.',
  internal_error: 'Triage failed unexpectedly. The incident was not changed.',
};

function TriagePanel({ triage, lastRun, running, onRun, relatedEventIds }: { triage: TriageInfo | null; lastRun: TriageRunSummary | null; running: boolean; onRun: () => void; relatedEventIds: string[] }) {
  const failed = lastRun && lastRun.status === 'failed';
  const newSince = triage ? relatedEventIds.filter(id => !triage.inputEventIds.includes(id)).length : 0;
  const changed = (before: string | null, after: string) => (before && before !== after ? `${before} → ${after}` : after);
  return <Panel title="Triage Agent" meta={triage ? (triage.method === 'llm' ? 'LLM ASSESSMENT · VALIDATED' : 'RULE-BASED FALLBACK') : 'NOT RUN'} actions={<button className="button primary" style={{ minHeight: 30 }} onClick={onRun} disabled={running} data-testid="button-run-triage">{running ? <RefreshCw size={13} className="spin" /> : <Play size={13} />}{triage ? 'Re-run triage' : 'Run Triage Agent'}</button>}>
    <div className="panel-body" data-testid="panel-triage">
      {running && <p className="mono muted" style={{ margin: '0 0 12px' }}>Triage in progress · local LLM inference can take up to a minute…</p>}
      {failed && <div className="error-box" style={{ marginBottom: 12 }} data-testid="triage-failure"><strong>Triage failed · {lastRun.outcome.replace(/_/g, ' ')}</strong><div style={{ marginTop: 6 }}>{OUTCOME_TEXT[lastRun.outcome] ?? 'The incident was not changed.'}</div>{lastRun.errors.slice(0, 3).map(e => <div key={e} className="mono muted" style={{ marginTop: 4, overflowWrap: 'anywhere' }}>{e}</div>)}</div>}
      {!triage && !failed && !running && <p className="page-subtitle" style={{ margin: 0 }}>Triage assesses severity, priority, category and whether investigation is needed. It reads incident evidence only and changes nothing in the cloud.</p>}
      {triage && <>
        {newSince > 0 && <div className="mono" style={{ color: '#e7cf63', marginBottom: 10 }}>{newSince} new correlated event(s) since this triage — re-run to include them.</div>}
        <div className="kv-list" data-testid="triage-result">{[
          ['Triage status', triage.method === 'llm' ? 'Completed (LLM, validated)' : 'Completed (rule-based fallback, no LLM)'],
          ['Severity', changed(triage.previous.severity, triage.severity)],
          ['Priority', changed(triage.previous.priority, triage.priority)],
          ['Category', changed(triage.previous.category, triage.category).toUpperCase()],
          ['Confidence', `${triage.confidence}% (in this assessment)`],
          ['Classification', triage.classification],
          ['Investigation required', triage.investigationRequired ? 'Yes' : 'No'],
          ['Recommended next step', triage.nextStep.toUpperCase()],
          ['Model / provider', `${triage.model} · ${triage.provider}`],
          ['Timestamp', triage.timestamp],
        ].map(([key, value]) => <div className="kv" key={key}><span className="key">{key}</span><span className="val mono" style={key === 'Severity' || key === 'Recommended next step' ? { color: 'hsl(var(--secondary))' } : undefined}>{value}</span></div>)}</div>
        <div className="eyebrow" style={{ marginTop: 16 }}>Interpretation · model output</div>
        <p className="page-subtitle" style={{ margin: '6px 0' }}>{triage.summary}</p>
        <p className="mono muted" style={{ margin: '4px 0' }}>Severity: {triage.severityRationale}</p>
        <p className="mono muted" style={{ margin: '4px 0' }}>Priority: {triage.priorityRationale}</p>
        <p className="mono muted" style={{ margin: '4px 0' }}>Investigation: {triage.investigationReason}</p>
        <div className="eyebrow" style={{ marginTop: 12 }}>Risk indicators · interpretation</div>
        {triage.riskIndicators.map(r => <div key={r.indicator} className="mono" style={{ marginTop: 5 }}>• {r.indicator} <span className="muted">[{r.refs.join(', ')}]</span></div>)}
        <div className="eyebrow" style={{ marginTop: 12 }}>Key evidence · observed facts from incident data</div>
        {triage.observed.map(o => <div key={o.ref} className="mono muted" style={{ marginTop: 5, overflowWrap: 'anywhere' }}><span style={{ color: 'hsl(var(--accent))' }}>{o.ref}</span> {o.fact}</div>)}
      </>}
    </div>
  </Panel>;
}


const INV_OUTCOME_TEXT: Record<string, string> = {
  triage_required: 'Triage required before investigation. Run the Triage Agent first (it is not run automatically).',
  insufficient_context: 'The incident has no event evidence to investigate.',
  llm_unavailable: 'The LLM is not reachable (is Ollama running?). The incident was not changed.',
  llm_not_configured: 'No LLM provider is configured (LLM_PROVIDER=none). The incident was not changed.',
  llm_error: 'The LLM returned an error. The incident was not changed.',
  invalid_llm_output: 'The model output failed validation (after one repair attempt). The incident was not changed.',
  policy_violation: 'The model output broke an investigation policy rule and was rejected. The incident was not changed.',
  internal_error: 'Investigation failed unexpectedly. The incident was not changed.',
};
const CERTAINTY_KIND: Record<string, string> = { confirmed: 'active', suspected: 'review', possible: 'idle', unsupported: 'idle' };

function InvestigationPanel({ investigation, lastRun, running, triaged, onRun }: { investigation: InvestigationInfo | null; lastRun: InvestigationRunSummary | null; running: boolean; triaged: boolean; onRun: () => void }) {
  const failed = lastRun && lastRun.status !== 'success';
  const inv = investigation;
  const section = (label: string) => <div className="eyebrow" style={{ marginTop: 14 }}>{label}</div>;
  return <Panel title="Investigator Agent" meta={inv ? (inv.method === 'llm' ? 'LLM INVESTIGATION · VALIDATED' : 'RULE-BASED FALLBACK') : 'NOT RUN'} actions={<button className="button primary" style={{ minHeight: 30, ...(triaged ? {} : { opacity: 0.45, cursor: 'not-allowed' }) }} onClick={onRun} disabled={running || !triaged} data-testid="button-run-investigation">{running ? <RefreshCw size={13} className="spin" /> : <Play size={13} />}{inv ? 'Re-run investigation' : 'Run Investigation Agent'}</button>}>
    <div className="panel-body" data-testid="panel-investigation">
      {!triaged && <p className="mono" style={{ margin: '0 0 10px', color: '#e7cf63' }} data-testid="investigation-triage-required">Triage required before investigation.</p>}
      {running && <p className="mono muted" style={{ margin: '0 0 12px' }}>Investigation in progress · the local model analyses the evidence catalog, this can take a minute or two…</p>}
      {failed && <div className="error-box" style={{ marginBottom: 12 }} data-testid="investigation-failure"><strong>{lastRun.status === 'skipped' ? 'Investigation skipped' : 'Investigation failed'} · {lastRun.outcome.replace(/_/g, ' ')}</strong><div style={{ marginTop: 6 }}>{INV_OUTCOME_TEXT[lastRun.outcome] ?? 'The incident was not changed.'}</div>{lastRun.errors.slice(0, 3).map(e => <div key={e} className="mono muted" style={{ marginTop: 4, overflowWrap: 'anywhere' }}>{e}</div>)}</div>}
      {!inv && !failed && !running && triaged && <p className="page-subtitle" style={{ margin: 0 }}>The Investigator builds a timeline, entity relationships and MITRE candidates from the incident's evidence, then a validated model analysis. It is read-only and never changes the Triage result.</p>}
      {inv && <div data-testid="investigation-result">
        <div className="kv-list">{[
          ['Investigation status', inv.method === 'llm' ? 'Completed (LLM, validated)' : 'Completed (rule-based fallback, no LLM)'],
          ['Method', inv.method], ['Provider / model', `${inv.provider} · ${inv.model}`],
          ['Confidence', `${inv.confidence}% (evidence supports the conclusion)`],
          ['Recommended next step', inv.nextStep.replace(/_/g, ' ').toUpperCase()], ['Timestamp', inv.timestamp],
        ].map(([key, value]) => <div className="kv" key={key}><span className="key">{key}</span><span className="val mono" style={key === 'Recommended next step' ? { color: 'hsl(var(--secondary))' } : undefined}>{value}</span></div>)}</div>
        {section('Investigation summary · interpretation')}
        <p className="page-subtitle" style={{ margin: '6px 0' }}>{inv.summary}</p>
        {section(`Timeline · ${inv.timeline.length} events (system-built; notes are interpretation)`)}
        {inv.timeline.map(t => <div key={t.id} className="mono" style={{ marginTop: 6, overflowWrap: 'anywhere' }}><span style={{ color: 'hsl(var(--accent))' }}>{t.id}</span> {t.time.slice(11)} <strong>{t.event}</strong>{t.gap !== null && <span className="muted"> · +{t.gap}s</span>}{t.shares.length > 0 && <span className="muted"> · {t.shares.map(x => x.replace(/_/g, ' ')).join(', ')}</span>}{t.note && <div className="muted" style={{ marginLeft: 22 }}>↳ {t.note}</div>}</div>)}
        {section(`Entities · ${inv.entities.length}`)}
        <div className="tool-row" style={{ marginTop: 6 }}>{inv.entities.filter(e => e.type !== 'account' && e.type !== 'region').map(e => <span className="tool" key={e.id} title={`evidence: ${e.evidenceIds.join(', ')}`}>{e.type}: {e.value}</span>)}</div>
        {inv.relationships.slice(0, 12).map(r => <div key={r.from + r.relation + r.to} className="mono muted" style={{ marginTop: 4, overflowWrap: 'anywhere' }}>{r.from} <span style={{ color: 'hsl(var(--accent))' }}>{r.relation.replace(/_/g, ' ')}</span> {r.to}{r.certainty !== 'confirmed' && <span style={{ color: '#e7cf63' }}> [{r.certainty}]</span>}</div>)}
        {section('Attack sequence · only evidence-supported stages are confirmed')}
        {inv.stages.map(st => <div key={st.order} className="mono" style={{ marginTop: 6, overflowWrap: 'anywhere' }}>{st.order}. <strong>{st.stage.replace(/_/g, ' ')}</strong> <Badge kind={CERTAINTY_KIND[st.certainty] ?? ''}>{st.certainty}</Badge> <span className="muted">{st.description}</span> {st.evidenceIds.length > 0 && <span style={{ color: 'hsl(var(--accent))' }}>[{st.evidenceIds.join(', ')}]</span>}{st.note && <div style={{ marginLeft: 22, color: '#e7cf63' }}>↳ proposed “{st.proposed}”; {st.note}</div>}</div>)}
        {section('Findings')}
        {inv.findings.map(f => <div key={f.id} className="mono" style={{ marginTop: 6, overflowWrap: 'anywhere' }}><span style={{ color: 'hsl(var(--accent))' }}>{f.id}</span> {f.type.replace(/_/g, ' ')} <Badge kind={CERTAINTY_KIND[f.classification] ?? ''}>{f.classification}</Badge> <span className="muted">conf {f.confidence}%</span><div className="muted" style={{ marginLeft: 22 }}>{f.statement} [{f.evidenceIds.join(', ')}]</div>{f.note && <div style={{ marginLeft: 22, color: '#e7cf63' }}>↳ backend: {f.note}</div>}</div>)}
        {section('MITRE ATT&CK · status decided by the backend')}
        {inv.mitre.length ? inv.mitre.map(m => <div key={m.id} className="mono" style={{ marginTop: 6, overflowWrap: 'anywhere' }}><strong>{m.id}</strong> {m.name} <span className="muted">({m.tactic})</span> <Badge kind={m.status === 'confirmed' ? 'active' : 'idle'}>{m.status}</Badge> <span className="muted">conf {m.confidence}%</span> <span style={{ color: 'hsl(var(--accent))' }}>[{m.evidenceIds.join(', ')}]</span><div className="muted" style={{ marginLeft: 22 }}>{m.rationale}</div><div className="muted" style={{ marginLeft: 22 }}>↳ {m.note}</div></div>) : <div className="mono muted" style={{ marginTop: 6 }}>No technique was supported by the evidence.</div>}
        {section('Root cause hypothesis · HYPOTHESIS, not fact')}
        <p className="page-subtitle" style={{ margin: '6px 0' }}>{inv.rootCause}</p>
        {section('Unknowns')}
        {inv.unknowns.map(u => <div key={u} className="mono muted" style={{ marginTop: 4 }}>? {u}</div>)}
        {inv.limitations.length > 0 && <>{section('Evidence limitations (system-derived)')}{inv.limitations.map(u => <div key={u} className="mono muted" style={{ marginTop: 4 }}>• {u}</div>)}</>}
        {inv.alternatives.length > 0 && <>{section('Alternative hypotheses')}{inv.alternatives.map(u => <div key={u} className="mono muted" style={{ marginTop: 4 }}>◦ {u}</div>)}</>}
        {section('Later stages')}
        <div className="mono muted" style={{ marginTop: 4 }}>Remediation · Verification — pending (not implemented yet)</div>
      </div>}
    </div>
  </Panel>;
}

const COMPLIANCE_OUTCOME_TEXT: Record<string, string> = {
  investigation_required: 'Investigation required before compliance assessment. Run the Investigator Agent first (it is not run automatically).',
  llm_unavailable: 'The LLM is not reachable (is Ollama running?). The incident was not changed.',
  llm_not_configured: 'No LLM provider is configured (LLM_PROVIDER=none). The incident was not changed.',
  llm_error: 'The LLM returned an error. The incident was not changed.',
  invalid_llm_output: 'The model output failed validation (after one repair attempt). The incident was not changed.',
  policy_violation: 'The model output broke a compliance policy rule and was rejected. The incident was not changed.',
  internal_error: 'Compliance assessment failed unexpectedly. The incident was not changed.',
};
const COMPLIANCE_KIND: Record<string, string> = { violation: 'critical', potential_violation: 'high', potential_gap: 'review', compliant: 'active', not_applicable: 'idle', unknown: 'idle' };
const label = (value: string) => value.replace(/_/g, ' ');

function CompliancePanel({ compliance, investigationRunId, lastRun, running, investigated, onRun }: { compliance: ComplianceInfo | null; investigationRunId: string | null; lastRun: ComplianceRunSummary | null; running: boolean; investigated: boolean; onRun: () => void }) {
  const failed = lastRun && lastRun.status !== 'success';
  const c = compliance;
  const stale = c !== null && investigationRunId !== null && c.basedOnInvestigationRun !== investigationRunId;
  const section = (text: string) => <div className="eyebrow" style={{ marginTop: 14 }}>{text}</div>;
  const refs = (ids: string[]) => ids.length > 0 && <span style={{ color: 'hsl(var(--accent))' }}> [{ids.join(', ')}]</span>;
  return <Panel title="Compliance Agent" meta={c ? (c.method === 'llm' ? 'LLM ASSESSMENT · VALIDATED' : 'RULE-BASED FALLBACK') : 'NOT RUN'} actions={<button className="button primary" style={{ minHeight: 30, ...(investigated ? {} : { opacity: 0.45, cursor: 'not-allowed' }) }} onClick={onRun} disabled={running || !investigated} data-testid="button-run-compliance">{running ? <RefreshCw size={13} className="spin" /> : <Play size={13} />}{c ? 'Re-run compliance' : 'Run Compliance Agent'}</button>}>
    <div className="panel-body" data-testid="panel-compliance">
      {!investigated && <p className="mono" style={{ margin: '0 0 10px', color: '#e7cf63' }} data-testid="compliance-investigation-required">Investigation required before compliance assessment.</p>}
      {running && <p className="mono muted" style={{ margin: '0 0 12px' }}>Compliance assessment in progress · the local model maps the evidence to configured controls, this can take a few minutes…</p>}
      {failed && <div className="error-box" style={{ marginBottom: 12 }} data-testid="compliance-failure"><strong>{lastRun.status === 'skipped' ? 'Compliance assessment skipped' : 'Compliance assessment failed'} · {label(lastRun.outcome)}</strong><div style={{ marginTop: 6 }}>{COMPLIANCE_OUTCOME_TEXT[lastRun.outcome] ?? 'The incident was not changed.'}</div>{lastRun.errors.slice(0, 3).map(e => <div key={e} className="mono muted" style={{ marginTop: 4, overflowWrap: 'anywhere' }}>{e}</div>)}</div>}
      {!c && !failed && !running && investigated && <p className="page-subtitle" style={{ margin: 0 }}>Maps the investigated incident to the project's configured security controls and framework mappings, separates control gaps from potential violations, and states what is unknown. Read-only; a security-engineering aid, not legal advice.</p>}
      {stale && <div className="mono" style={{ color: '#e7cf63', marginBottom: 10 }} data-testid="compliance-stale">The incident was re-investigated after this assessment — re-run compliance.</div>}
      {c && <div data-testid="compliance-result">
        <div className="kv-list">{[
          ['Compliance status', c.method === 'llm' ? 'Completed (LLM, validated)' : 'Completed (rule-based fallback, no LLM)'],
          ['Method', c.method], ['Provider / model', `${c.provider} · ${c.model}`],
          ['Confidence', `${c.confidence}% (in this assessment)`], ['Timestamp', c.timestamp],
        ].map(([key, value]) => <div className="kv" key={key}><span className="key">{key}</span><span className="val mono">{value}</span></div>)}
          <div className="kv"><span className="key">Overall compliance status</span><span className="val"><Badge kind={COMPLIANCE_KIND[c.overallStatus] ?? ''}>{label(c.overallStatus)}</Badge></span></div>
          <div className="kv"><span className="key">Reporting</span><span className="val mono">{label(c.reportingStatus)}</span></div></div>
        <p className="mono muted" style={{ margin: '6px 0 0' }}>{c.overallNote}</p>
        {section('Compliance summary · interpretation')}
        <p className="page-subtitle" style={{ margin: '6px 0' }}>{c.summary}</p>
        {section(`Affected assets · ${c.assets.length} (backend-observed)`)}
        {c.assets.map(a => <div key={a.id} className="mono" style={{ marginTop: 5, overflowWrap: 'anywhere' }}><span style={{ color: 'hsl(var(--accent))' }}>{a.id}</span> {a.identifier} <Badge kind={a.classification === 'unknown' ? 'idle' : a.classification === 'public' ? 'active' : 'review'}>{a.classification}</Badge><span className="muted"> {a.environment ?? 'environment unknown'} · owner {a.owner ?? 'unknown'}</span></div>)}
        {section('Affected data · configured classification only')}
        {c.data.length ? c.data.map(d => <div key={d.id} className="mono muted" style={{ marginTop: 4, overflowWrap: 'anywhere' }}>{d.identifier}: <strong>{d.classification}</strong> — {d.basis}</div>) : <div className="mono muted" style={{ marginTop: 4 }}>No classified data is configured for the affected assets.</div>}
        {section(`Security controls · ${c.controls.length}`)}
        {c.controls.map(x => <div key={x.id} className="mono" style={{ marginTop: 7, overflowWrap: 'anywhere' }}><strong>{x.name}</strong> <Badge kind={COMPLIANCE_KIND[x.status] ?? ''}>{label(x.status)}</Badge> <span className="muted">conf {x.confidence}%</span>{refs(x.evidenceIds)}<div className="muted" style={{ marginLeft: 16 }}>{x.rationale}</div>{x.note && <div style={{ marginLeft: 16, color: '#e7cf63' }}>↳ backend: proposed “{label(x.proposed)}”; {x.note}</div>}</div>)}
        {section(`Framework assessments · ${c.frameworks.length} (configured mappings only)`)}
        {c.frameworks.map(f => <div key={f.framework + f.controlId + f.control} className="mono" style={{ marginTop: 4, overflowWrap: 'anywhere' }}><span style={{ color: 'hsl(var(--accent))' }}>{f.framework}</span> {f.controlId} <span className="muted">{f.title}</span> <Badge kind={COMPLIANCE_KIND[f.status] ?? ''}>{label(f.status)}</Badge> <span className="muted">via {label(f.control)} · {f.source === 'llm' ? 'model-assessed' : 'derived from control'}</span></div>)}
        {section('Control gaps')}
        {c.gaps.length ? c.gaps.map(g => <div key={g.control + g.description} className="mono" style={{ marginTop: 5, overflowWrap: 'anywhere' }}><strong>{g.name}</strong>{refs(g.evidenceIds)}<div className="muted" style={{ marginLeft: 16 }}>{g.description}</div></div>) : <div className="mono muted" style={{ marginTop: 4 }}>No control gap was identified from the evidence.</div>}
        {section('Potential violations · configured rules only')}
        {c.violations.length ? c.violations.map(v => <div key={v.control + v.statement} className="mono" style={{ marginTop: 5, overflowWrap: 'anywhere' }}><strong>{v.name}</strong> <Badge kind={COMPLIANCE_KIND[v.status] ?? ''}>{label(v.status)}</Badge> <span className="muted">{v.ruleId ? `rule ${v.ruleId}` : 'no configured rule'}</span>{refs(v.evidenceIds)}<div className="muted" style={{ marginLeft: 16 }}>{v.statement}</div>{v.note && <div style={{ marginLeft: 16, color: '#e7cf63' }}>↳ backend: {v.note}</div>}</div>) : <div className="mono muted" style={{ marginTop: 4 }}>No potential violation was identified.</div>}
        {c.violationRules.length > 0 && <div className="mono muted" style={{ marginTop: 6 }}>Configured violation rule(s) matched by the backend: {c.violationRules.map(r => r.id).join(', ')}</div>}
        {section('Reporting considerations · internal rules only, no legal advice')}
        {c.reporting.map(r => <div key={r.note} className="mono" style={{ marginTop: 5, overflowWrap: 'anywhere' }}><Badge kind={r.status === 'configured_requirement' ? 'review' : 'idle'}>{label(r.status)}</Badge> {r.ruleId && <span className="muted">rule {r.ruleId}{r.requirement ? ` · ${label(r.requirement)}` : ''}</span>}{refs(r.evidenceIds)}<div className="muted" style={{ marginLeft: 16 }}>{r.note}</div></div>)}
        {section('Recommendations · reviews only, nothing is executed')}
        {c.recommendations.map(r => <div key={r.type + r.rationale} className="mono" style={{ marginTop: 5, overflowWrap: 'anywhere' }}>• <strong>{label(r.type)}</strong>{r.control && <span className="muted"> · {label(r.control)}</span>}{refs(r.evidenceIds)}<div className="muted" style={{ marginLeft: 16 }}>{r.rationale}</div></div>)}
        {section('Unknowns')}
        {[...c.unknowns, ...c.standingUnknowns.filter(u => !c.unknowns.includes(u))].map(u => <div key={u} className="mono muted" style={{ marginTop: 4 }}>? {u}</div>)}
        {section('Later stages')}
        <div className="mono muted" style={{ marginTop: 4 }}>Remediation · Verification — pending (not implemented yet)</div>
      </div>}
    </div>
  </Panel>;
}



const REMEDIATION_OUTCOME_TEXT: Record<string, string> = {
  compliance_required: 'Compliance assessment required before remediation planning. Run the Compliance Agent first (it is not run automatically).',
  llm_unavailable: 'The LLM is not reachable (is Ollama running?). No approval was created and nothing was changed.',
  llm_not_configured: 'No LLM provider is configured (LLM_PROVIDER=none). No approval was created.',
  llm_error: 'The LLM returned an error. No approval was created and nothing was changed.',
  invalid_llm_output: 'The model proposal failed validation (invalid action, target or evidence, after one repair attempt). No approval was created and nothing was changed.',
  policy_violation: 'The model proposal broke a remediation policy rule and was rejected. No approval was created and nothing was changed.',
  already_remediated: 'The proposed action was already executed and the target is already in the desired state. Nothing to do.',
  incident_not_remediable: 'This incident is not in a state that allows remediation planning.',
  internal_error: 'Remediation planning failed unexpectedly. Nothing was changed.',
};
const DECISION_TEXT: Record<string, string> = {
  executed: 'Approved and executed through the ToolExecutor; the cloud state was read back and confirms the change.',
  rejected: 'Proposal rejected. Nothing was executed.',
  actions_disabled: 'Approved, but agent actions are disabled (kill switch AGENT_ACTIONS_ENABLED=false). Nothing was executed.',
  stale_remediation_plan: 'The cloud state changed after the plan was made. Nothing was executed; run remediation again.',
  already_remediated: 'The target is already in the desired state (or the action already ran). Nothing was executed.',
  policy_blocked: 'Remediation policy no longer allows this action. Nothing was executed.',
  approval_expired: 'The approval expired. Nothing was executed; run remediation again.',
  proposal_tampered: 'The stored proposal no longer matches its approval. Nothing was executed.',
  plan_mismatch: 'This approval is not for the incident\'s current plan. Nothing was executed.',
  invalid_target: 'The target no longer exists. Nothing was executed.',
  execution_failed: 'The action failed. See the execution details.',
  readback_mismatch: 'The tool reported success but the cloud state does not show the change. Marked failed.',
};
const EXEC_KIND: Record<string, string> = { executed: 'active', pending_approval: 'review', approved: 'review', blocked: 'high', failed: 'critical', rejected: 'idle', not_executed: 'idle' };
const stateLine = (state: Record<string, unknown> | null) => state ? Object.entries(state).filter(([key]) => key !== 'access_key_last_used_ips').map(([key, value]) => `${key}=${String(value)}`).join(', ') : '—';

function RemediationPanel({ remediation, complianceRunId, lastRun, running, assessed, deciding, onRun, onDecide }: { remediation: RemediationInfo | null; complianceRunId: string | null; lastRun: RemediationRunSummary | null; running: boolean; assessed: boolean; deciding: boolean; onRun: () => void; onDecide: (approvalId: string, decision: 'approve' | 'reject' | 'execute') => void }) {
  const r = remediation; const failed = lastRun && lastRun.status !== 'success';
  const stale = r !== null && complianceRunId !== null && r.basedOnComplianceRun !== complianceRunId;
  const pendingApproval = r !== null && r.approval?.status === 'pending' && r.plan.action !== 'no_action';
  const retry = r !== null && r.approval?.status === 'approved' && r.execution.status === 'blocked' && r.execution.reasonCode === 'actions_disabled';
  const section = (text: string) => <div className="eyebrow" style={{ marginTop: 14 }}>{text}</div>;
  const refs = (ids: string[]) => ids.length > 0 && <span style={{ color: 'hsl(var(--accent))' }}> [{ids.join(', ')}]</span>;
  return <Panel title="Remediation Agent" meta={r ? (r.method === 'llm' ? 'LLM PLAN · VALIDATED · HUMAN APPROVAL' : r.method === 'rule_based_fallback' ? 'RULE-BASED FALLBACK · HUMAN APPROVAL' : 'DETERMINISTIC · NO CANDIDATE ACTION') : 'NOT RUN'} actions={<button className="button primary" style={{ minHeight: 30, ...(assessed ? {} : { opacity: 0.45, cursor: 'not-allowed' }) }} onClick={onRun} disabled={running || deciding || !assessed} data-testid="button-run-remediation">{running ? <RefreshCw size={13} className="spin" /> : <Play size={13} />}{r ? 'Re-run remediation planning' : 'Run Remediation Agent'}</button>}>
    <div className="panel-body" data-testid="panel-remediation">
      {!assessed && <p className="mono" style={{ margin: '0 0 10px', color: '#e7cf63' }} data-testid="remediation-compliance-required">Compliance assessment required before remediation planning.</p>}
      {running && <p className="mono muted" style={{ margin: '0 0 12px' }}>Remediation planning in progress · the local model chooses among the backend's allowed actions; this can take a few minutes…</p>}
      {failed && <div className="error-box" style={{ marginBottom: 12 }} data-testid="remediation-failure"><strong>{lastRun.status === 'skipped' ? 'Remediation planning skipped' : 'Remediation planning failed'} · {label(lastRun.outcome)}</strong><div style={{ marginTop: 6 }}>{REMEDIATION_OUTCOME_TEXT[lastRun.outcome] ?? 'No approval was created and nothing was changed.'}</div>{lastRun.errors.slice(0, 3).map(e => <div key={e} className="mono muted" style={{ marginTop: 4, overflowWrap: 'anywhere' }}>{e}</div>)}</div>}
      {!r && !failed && !running && assessed && <p className="page-subtitle" style={{ margin: 0 }}>The backend determines which allow-listed actions apply to the current cloud state; the local model only chooses one (or none) and explains why. Planning changes nothing: a human must approve, then the backend re-validates and executes through the ToolExecutor.</p>}
      {stale && <div className="mono" style={{ color: '#e7cf63', marginBottom: 10 }} data-testid="remediation-stale">The compliance assessment changed after this plan — re-run remediation planning.</div>}
      {r && <div data-testid="remediation-result">
        <div className="mono muted" style={{ marginBottom: 10 }} data-testid="remediation-progress">Plan generated ✓ · Approval: {r.plan.action === 'no_action' ? 'not needed' : label(r.approval?.status ?? 'pending')} · Execution: {label(r.execution.status)}</div>
        <div className="kv-list">{[
          ['Remediation status', label(r.status)], ['Method', r.method], ['Provider / model', `${r.provider} · ${r.model}`],
          ['Confidence', `${r.confidence}% (in this plan)`], ['Timestamp', r.timestamp],
          ['Recommended action', r.plan.action === 'no_action' ? 'no action' : label(r.plan.action)], ['Target', r.plan.target ?? '—'],
          ['Risk (set by policy)', r.plan.risk], ['Rollback available', r.plan.rollbackAvailable ? 'yes' : 'no'],
        ].map(([key, value]) => <div className="kv" key={key}><span className="key">{key}</span><span className="val mono">{value}</span></div>)}
          <div className="kv"><span className="key">Approval status</span><span className="val"><Badge kind={r.approval?.status === 'approved' ? 'active' : r.approval?.status === 'pending' ? 'review' : 'idle'}>{r.plan.action === 'no_action' ? 'not required' : label(r.approval?.status ?? 'pending')}</Badge></span></div>
          <div className="kv"><span className="key">Execution status</span><span className="val"><Badge kind={EXEC_KIND[r.execution.status] ?? ''}>{label(r.execution.status)}</Badge></span></div></div>
        {r.execution.message && <p className="mono muted" style={{ margin: '6px 0 0', overflowWrap: 'anywhere' }} data-testid="remediation-execution-message">{r.execution.reasonCode && <strong>{label(r.execution.reasonCode)} · </strong>}{r.execution.message}</p>}
        {pendingApproval && r.approval && <div className="panel" style={{ marginTop: 14, border: '1px solid hsl(var(--primary))' }} data-testid="approval-card"><div className="panel-body">
          <div className="eyebrow" style={{ color: 'hsl(var(--primary))' }}>REMEDIATION REQUEST · {r.approval.id}</div>
          <div className="kv-list" style={{ marginTop: 8 }}>{[['Action', label(r.plan.action)], ['Target', r.plan.target ?? '—'], ['Risk', r.plan.risk], ['Evidence', r.plan.evidenceIds.join(', ') || '—'], ['Expires', r.approval.expiresAt]].map(([key, value]) => <div className="kv" key={key}><span className="key">{key}</span><span className="val mono">{value}</span></div>)}</div>
          <p className="page-subtitle" style={{ margin: '10px 0 0' }}><strong>Reason:</strong> {r.plan.reason}</p>
          <p className="mono" style={{ margin: '10px 0', color: '#e7cf63' }} data-testid="approval-warning">⚠ This action will modify the simulated cloud state.</p>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between' }}><button className="button danger" onClick={() => onDecide(r.approval!.id, 'reject')} disabled={deciding} data-testid="button-reject-remediation"><X size={13} />Reject</button><button className="button lime" onClick={() => onDecide(r.approval!.id, 'approve')} disabled={deciding} data-testid="button-approve-remediation">{deciding ? <RefreshCw size={13} className="spin" /> : <Check size={13} />}Approve</button></div>
        </div></div>}
        {retry && r.approval && <div style={{ marginTop: 12 }}><button className="button lime" onClick={() => onDecide(r.approval!.id, 'execute')} disabled={deciding} data-testid="button-execute-remediation"><Play size={13} />Execute approved action</button><span className="mono muted" style={{ marginLeft: 10 }}>enable AGENT_ACTIONS_ENABLED on the backend first</span></div>}
        {section('Reason · model interpretation')}
        <p className="page-subtitle" style={{ margin: '6px 0' }}>{r.plan.reason}{refs(r.plan.evidenceIds)}</p>
        {section('Expected effect')}
        <p className="page-subtitle" style={{ margin: '6px 0' }}>{r.plan.expectedEffect}</p>
        {r.plan.policyNotes.map(n => <div key={n.field} className="mono" style={{ marginLeft: 16, color: '#e7cf63' }}>↳ backend: {n.field} proposed “{n.proposed}”, set to “{n.final}” — {n.note}</div>)}
        {section('Rollback')}
        <div className="mono muted" style={{ marginTop: 4 }}>{r.plan.rollbackDescription}</div>
        {section('Evidence · backend-resolved')}
        {r.evidence.map(e => <div key={e.id} className="mono" style={{ marginTop: 4, overflowWrap: 'anywhere' }}><span style={{ color: 'hsl(var(--accent))' }}>{e.id}</span> <span className="muted">{e.observed ? 'observed' : 'opinion'} · {e.source}</span> {e.description}</div>)}
        {section('Before state')}
        <div className="code-block" style={{ marginTop: 6 }} data-testid="remediation-before">{stateLine(r.execution.before ?? r.before)}</div>
        {section('After state · read back from the cloud')}
        <div className="code-block" style={{ marginTop: 6 }} data-testid="remediation-after">{r.execution.after || r.after ? stateLine(r.execution.after ?? r.after) : 'not executed yet'}</div>
        {r.plan.excluded.length > 0 && <>{section('Not proposed · refused by the backend')}{r.plan.excluded.map(x => <div key={x} className="mono muted" style={{ marginTop: 4, overflowWrap: 'anywhere' }}>• {x}</div>)}</>}
        {section('Unknowns')}
        {r.unknowns.length ? r.unknowns.map(u => <div key={u} className="mono muted" style={{ marginTop: 4 }}>? {u}</div>) : <div className="mono muted" style={{ marginTop: 4 }}>None stated.</div>}
        {section('Later stages')}
        <div className="mono muted" style={{ marginTop: 4 }}>Verification — pending (not implemented yet)</div>
      </div>}
    </div>
  </Panel>;
}


const VERIFICATION_OUTCOME_TEXT: Record<string, string> = {
  remediation_not_ready: 'The remediation is not ready to verify (no remediation yet, or it is still pending approval). Nothing was read or changed.',
  remediation_not_executed: 'The remediation was not executed (rejected, blocked or no action). There is nothing to verify.',
  internal_error: 'Verification failed unexpectedly. Nothing was changed.',
};
const VERIFICATION_KIND: Record<string, string> = { verified: 'active', failed: 'critical', partial: 'high', unknown: 'review', skipped: 'idle' };
const VERIFICATION_HEADLINE: Record<string, string> = {
  verified: '✓ VERIFIED', failed: '✗ FAILED', partial: '◐ PARTIAL', unknown: '? UNKNOWN',
};
const showValue = (value: unknown) => value === null || value === undefined ? '—' : String(value);

function VerificationPanel({ verification, remediation, lastRun, running, onRun }: { verification: VerificationInfo | null; remediation: RemediationInfo | null; lastRun: VerificationRunSummary | null; running: boolean; onRun: () => void }) {
  const v = verification; const failed = lastRun && lastRun.status === 'skipped';
  const execStatus = remediation?.execution.status ?? null;
  const canRun = remediation !== null && remediation.plan.action !== 'no_action' && (execStatus === 'executed' || execStatus === 'failed');
  const blockedText = remediation === null ? 'No remediation yet — run the Remediation Agent first.' : remediation.plan.action === 'no_action' ? 'The remediation proposed no action — nothing to verify.' : execStatus === 'pending_approval' ? 'Remediation is pending human approval — nothing to verify yet.' : execStatus === 'approved' ? 'Remediation is approved but has not executed yet.' : execStatus === 'rejected' ? 'The remediation was rejected — nothing was executed.' : execStatus === 'blocked' ? 'The remediation was blocked and did not execute.' : 'The remediation has not been executed.';
  const stale = v !== null && remediation !== null && v.basedOnRemediationRun !== remediation.runId;
  const section = (text: string) => <div className="eyebrow" style={{ marginTop: 14 }}>{text}</div>;
  return <Panel title="Verification Agent" meta={v ? 'DETERMINISTIC · READ-ONLY · NO LLM' : 'NOT RUN'} actions={<button className="button primary" style={{ minHeight: 30, ...(canRun ? {} : { opacity: 0.45, cursor: 'not-allowed' }) }} onClick={onRun} disabled={running || !canRun} data-testid="button-run-verification">{running ? <RefreshCw size={13} className="spin" /> : <Play size={13} />}{v ? 'Re-verify' : 'Run Verification'}</button>}>
    <div className="panel-body" data-testid="panel-verification">
      {!canRun && <p className="mono" style={{ margin: '0 0 10px', color: '#e7cf63' }} data-testid="verification-not-ready">{blockedText}</p>}
      {failed && lastRun && <div className="error-box" style={{ marginBottom: 12 }} data-testid="verification-skipped"><strong>Verification skipped · {label(lastRun.outcome)}</strong><div style={{ marginTop: 6 }}>{VERIFICATION_OUTCOME_TEXT[lastRun.outcome] ?? 'Nothing was changed.'}</div></div>}
      {!v && canRun && !running && <p className="page-subtitle" style={{ margin: 0 }}>Independently reads the target's current state and compares BEFORE / EXPECTED / ACTUAL. It does not trust the execution result, never executes, approves or retries anything, and can be repeated safely.</p>}
      {stale && <div className="mono" style={{ color: '#e7cf63', marginBottom: 10 }} data-testid="verification-stale">The remediation changed after this verification — re-verify.</div>}
      {v && <div data-testid="verification-result">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}><Badge kind={VERIFICATION_KIND[v.status] ?? ''}>{VERIFICATION_HEADLINE[v.status] ?? v.status.toUpperCase()}</Badge><span className="mono muted" data-testid="verification-status-text">Status: {v.status}</span></div>
        <div className="kv-list">{[
          ['Verification status', label(v.status)], ['Method', label(v.method)], ['Action', label(v.action)], ['Target', v.target ?? '—'],
          ['Confidence', v.confidence.toFixed(2)], ['Remediation reported', v.reportedExecution ? `${label(v.reportedExecution)} (not trusted)` : '—'], ['Timestamp', v.timestamp],
        ].map(([key, value]) => <div className="kv" key={key}><span className="key">{key}</span><span className="val mono">{value}</span></div>)}</div>
        {section('Expected effect')}
        <p className="page-subtitle" style={{ margin: '6px 0' }}>{v.expectedEffect}</p>
        {section('Before → expected → actual')}
        {v.comparison.length ? v.comparison.map(c => <div key={c.field} className="mono" style={{ marginTop: 6, overflowWrap: 'anywhere' }} data-testid={`comparison-${c.field}`}>
          <div className="muted">Before:&nbsp;&nbsp;&nbsp;{c.field} = {showValue(c.before)}</div>
          <div>Expected: {c.field} = {showValue(c.expected)}</div>
          <div style={{ color: c.satisfied ? 'hsl(var(--secondary))' : '#ff9a95' }}>Actual:&nbsp;&nbsp;&nbsp;{c.field} = {c.present ? showValue(c.actual) : 'missing'} {c.satisfied ? '✓' : '✗'}</div>
        </div>) : <div className="mono muted" style={{ marginTop: 4 }}>No comparison: the current state could not be read.</div>}
        {section('Before state')}
        <div className="code-block" style={{ marginTop: 6 }} data-testid="verification-before">{stateLine(v.beforeState)}</div>
        {section('Actual state · read now')}
        <div className="code-block" style={{ marginTop: 6 }} data-testid="verification-actual">{stateLine(v.actualState)}</div>
        {section('Verification reason')}
        <p className="page-subtitle" style={{ margin: '6px 0' }} data-testid="verification-reason">{v.reason}{v.failureReason && <span className="mono muted"> [{v.failureReason}]</span>}</p>
        {section('Evidence · backend-generated')}
        {v.evidence.map(e => <div key={e.id} className="mono" style={{ marginTop: 4, overflowWrap: 'anywhere' }}><span style={{ color: 'hsl(var(--accent))' }}>{e.id}</span> <span className="muted">{label(e.type)} · {e.source}</span> {stateLine(e.data)}</div>)}
        {section('Recommendations · nothing is retried automatically')}
        {v.recommendations.map(r => <div key={r} className="mono muted" style={{ marginTop: 4 }}>• {label(r)}</div>)}
      </div>}
    </div>
  </Panel>;
}


/* ------------------------------------------------------------- Phase 8 / 9 panels */
const AppCtx = createContext<{ notify: (title: string, message: string) => void; reload: () => Promise<void> }>({ notify: () => undefined, reload: async () => undefined });
const pct = (value: number) => `${Math.round(value * 100)}%`;
const RISK_KIND: Record<string, string> = { high: 'critical', medium: 'high', low: 'active' };
const FEEDBACK_KIND: Record<string, string> = { successful_response: 'active', failed_response: 'critical', partial_response: 'high', insufficient_evidence: 'review', regression_detected: 'critical', retry_requested: 'review' };
const RECOMMENDATION_TEXT: Record<string, string> = {
  retry_same_action: 'A human may request a retry (a new proposal that still needs approval).', alternative_action: 'Consider a different remediation action.',
  reinvestigate: 'Re-investigate the incident before acting again.', request_human_review: 'A human should review this response.',
  keep_incident_open: 'Keep the incident open.', monitor_resource: 'Keep monitoring the resource.', no_further_action: 'No further action is recommended.',
};

function MLPanel({ ml }: { ml: MLPredictionInfo | null }) {
  return <Panel title="ML Threat Analysis" meta="ML PREDICTION · DECISION SUPPORT">
    <div className="panel-body" data-testid="panel-ml">
      {!ml ? <p className="page-subtitle" style={{ margin: 0 }} data-testid="ml-none">No ML prediction is attached to this incident (no active model when the Monitor ran).</p> : <>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}><Badge kind={RISK_KIND[ml.riskLevel] ?? ''}>{ml.riskLevel.toUpperCase()} RISK</Badge><span className="mono muted">ML Prediction · not a confirmed attack</span></div>
        <div className="kv-list">{[['Prediction', label(ml.prediction)], ['Threat probability', pct(ml.threatProbability)], ['Predicted-class probability', pct(ml.predictionProbability)], ['Risk level', ml.riskLevel.toUpperCase()], ['Model', `${ml.modelType.replace('Classifier', '')} ${ml.modelVersion}`], ['Feature set / data', `${ml.featureVersion} · ${ml.dataSource}`]].map(([key, value]) => <div className="kv" key={key}><span className="key">{key}</span><span className="val mono" data-testid={`ml-${key.toLowerCase().replace(/[^a-z]+/g, '-')}`}>{value}</span></div>)}</div>
        <div className="eyebrow" style={{ marginTop: 12 }}>Signals · the model's most influential active features</div>
        {ml.features.map(f => <div key={f.name} className="mono" style={{ marginTop: 4 }}>• {f.description} <span className="muted">= {f.value}</span></div>)}
        <p className="mono muted" style={{ margin: '12px 0 0', overflowWrap: 'anywhere' }}>{ml.note}</p>
      </>}
    </div>
  </Panel>;
}

function FeedbackPanel({ incidentId, verification, remediation }: { incidentId: string; verification: VerificationInfo | null; remediation: RemediationInfo | null }) {
  const { notify, reload } = useContext(AppCtx);
  const [records, setRecords] = useState<LearningRecordInfo[]>([]); const [busy, setBusy] = useState(false); const [retryLimit, setRetryLimit] = useState<number | null>(null);
  const load = useCallback(async () => { try { setRecords(await getLearning(incidentId)); const stats = await getLearningStats(); setRetryLimit(stats?.service.retry_limit ?? null); } catch { setRecords([]); } }, [incidentId]);
  useEffect(() => { void load(); }, [load, verification?.runId]);
  const outcome = records.find(r => r.feedback !== 'retry_requested' && r.autoFeedback !== 'retry_requested' && r.autoFeedback !== 'regression_detected') ?? null;
  const regression = records.find(r => r.autoFeedback === 'regression_detected' && r.previousRunId === null && r.retryCount === 0) ?? null;
  const retries = records.filter(r => r.feedback === 'retry_requested');
  const limit = retryLimit ?? retries[0]?.retryLimit ?? 2;
  const canRetry = verification !== null && remediation !== null && (verification.status !== 'verified' || regression !== null) && retries.length < limit;
  const act = async (fn: () => Promise<void>) => { setBusy(true); try { await fn(); } finally { setBusy(false); } };
  const run = () => act(async () => { const r = await runFeedback(incidentId); if (r.ok && r.records.length) notify(r.regression ? 'Regression detected' : 'Learning record written', r.regression ? `${incidentId}: a verified resource is insecure again. Nothing was remediated automatically.` : `${incidentId}: ${label(r.records[0].feedback)}; recommendation ${label(r.records[0].recommendation)}.`); else notify('Feedback service skipped', r.message || label(r.outcome)); await load(); });
  const verdict = (feedback: 'correct' | 'incorrect' | 'partially_correct' | 'needs_review') => act(async () => { if (!outcome) return; const r = await submitFeedback(outcome.id, feedback); notify(r.ok ? 'Feedback recorded' : 'Feedback not recorded', r.ok ? `Your verdict (${label(feedback)}) overrides the inferred feedback.` : r.message); await load(); });
  const retry = () => act(async () => { const r = await requestRetry(incidentId, 'analyst requested a retry'); notify(r.ok ? 'Retry requested' : 'Retry not possible', r.ok ? `Retry ${r.retryCount}/${r.retryLimit}: a new remediation PROPOSAL was created (${label(r.remediationOutcome ?? 'no proposal')}). Nothing was executed; approval is still required.` : r.message); await load(); await reload(); });
  const stat = (key: string, value: string | number | null | undefined) => <div className="kv" key={key}><span className="key">{key}</span><span className="val mono">{value ?? '—'}</span></div>;
  return <Panel title="Feedback & Learning" meta="DETERMINISTIC BACKEND SERVICE · NOT AN LLM" actions={<button className="button primary" style={{ minHeight: 30, ...(verification ? {} : { opacity: 0.45, cursor: 'not-allowed' }) }} onClick={run} disabled={busy || !verification} data-testid="button-run-feedback">{busy ? <RefreshCw size={13} className="spin" /> : <Play size={13} />}Run feedback service</button>}>
    <div className="panel-body" data-testid="panel-feedback">
      {!verification && <p className="mono" style={{ margin: '0 0 10px', color: '#e7cf63' }} data-testid="feedback-not-ready">Verification required before the outcome can be recorded.</p>}
      {verification && !outcome && <p className="page-subtitle" style={{ margin: 0 }}>Classifies the verification outcome, analyses a failure with deterministic rules, and recommends recovery. It only recommends: any action still needs human approval, the kill switch and the ToolExecutor.</p>}
      {regression && <div className="error-box" style={{ marginBottom: 10 }} data-testid="feedback-regression"><strong>Regression detected</strong><div style={{ marginTop: 6 }}>The remediation was verified, but the resource no longer has the expected state. It was NOT remediated again automatically. {RECOMMENDATION_TEXT[regression.recommendation]}</div></div>}
      {outcome && <div data-testid="feedback-result">
        <div className="kv-list">
          {stat('Agent decision', `${outcome.action ? label(outcome.action) : '—'} on ${outcome.target ?? '—'}${outcome.providers.remediation ? ` (${outcome.providers.remediation})` : ''}`)}
          {stat('Remediation', remediation ? label(remediation.execution.status) : '—')}
          {stat('Verification', outcome.verificationStatus ? label(outcome.verificationStatus) : '—')}
          <div className="kv"><span className="key">Feedback</span><span className="val"><Badge kind={FEEDBACK_KIND[outcome.feedback] ?? ''}>{label(outcome.feedback)}</Badge>{outcome.humanFeedback && <span className="mono muted"> · analyst: {label(outcome.humanFeedback)} (inferred: {label(outcome.autoFeedback)})</span>}</span></div>
          {stat('Failure reason', outcome.failureReason ? label(outcome.failureReason) : 'none')}
          {stat('Recommendation', label(outcome.recommendation))}
          {stat('Retries used', `${retries.length} / ${limit}`)}
        </div>
        <p className="mono muted" style={{ margin: '8px 0 0' }} data-testid="feedback-recommendation-text">{RECOMMENDATION_TEXT[outcome.recommendation]}</p>
        <div className="eyebrow" style={{ marginTop: 12 }}>Analyst feedback · overrides the inferred type</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 8 }}>{(['correct', 'incorrect', 'partially_correct', 'needs_review'] as const).map(v => <button key={v} className={`button ${outcome.humanFeedback === v ? 'primary' : 'ghost'}`} style={{ minHeight: 30 }} disabled={busy} onClick={() => verdict(v)} data-testid={`button-feedback-${v}`}>{v === 'correct' ? 'Correct' : v === 'incorrect' ? 'Incorrect' : v === 'partially_correct' ? 'Partially Correct' : 'Needs Review'}</button>)}</div>
      </div>}
      {canRetry && <div style={{ marginTop: 14 }}><button className="button" disabled={busy} onClick={retry} data-testid="button-request-retry"><RefreshCw size={13} />Request retry ({retries.length}/{limit} used)</button><span className="mono muted" style={{ marginLeft: 10 }}>creates a new remediation proposal only — it needs your approval</span></div>}
      {verification && !canRetry && verification.status !== 'verified' && retries.length >= limit && <p className="mono" style={{ margin: '12px 0 0', color: '#e7cf63' }} data-testid="retry-limit-reached">Retry limit reached ({limit}). A human must decide how to proceed.</p>}
      {retries.map(r => <div key={r.id} className="mono muted" style={{ marginTop: 6, overflowWrap: 'anywhere' }} data-testid="retry-record">↻ retry {r.retryCount}/{r.retryLimit} · previous run {r.previousRunId} · {r.retryRunId ? `new proposal run ${r.retryRunId}` : 'no proposal yet'} · {r.retryReason}</div>)}
    </div>
  </Panel>;
}

function ServiceCards() {
  const [stats, setStats] = useState<LearningStats | null>(null); const [ml, setMl] = useState<MlStatus | null>(null); const [metrics, setMetrics] = useState<MlMetrics | null>(null);
  useEffect(() => { void (async () => { setStats(await getLearningStats()); const status = await getMlStatus(); setMl(status); setMetrics(status?.available ? await getMlMetrics() : null); })(); }, []);
  const l = stats?.learning; const perf = stats?.performance;
  const card = (key: string, value: string | number, meta: string, icon: any, accent?: string) => <StatCard key={key} label={key} value={String(value)} meta={meta} icon={icon} accent={accent} />;
  return <div style={{ marginTop: 14 }}>
    <Panel title="Feedback & Learning" meta="DETERMINISTIC BACKEND SERVICE · NOT AN LLM AGENT"><div className="panel-body" data-testid="panel-learning-stats">
      {!l ? <p className="mono muted">Learning statistics are not available (backend unreachable).</p> : <>
        <div className="grid-4">{[card('Learning records', l.total_learning_records, 'structured, no prompts or secrets', Database), card('Successful responses', l.successful_responses, 'verified', CheckCircle2, 'lime'), card('Failed responses', l.failed_responses, `${l.partial_responses} partial · ${l.insufficient_evidence} unknown`, AlertTriangle, 'amber'), card('Regressions', l.regressions, 'verified, then insecure again', ShieldAlert)]}</div>
        <div className="grid-4" style={{ marginTop: 12 }}>{[card('Human corrections', l.human_corrections, `${l.human_feedback_given} analyst verdict(s)`, Check, 'cyan'), card('Retry requests', l.retry_requests, `limit ${stats?.service.retry_limit ?? '—'} per incident`, RefreshCw), card('Verification success', perf?.verification_success_rate == null ? '—' : pct(perf.verification_success_rate), `${perf?.verification_runs_with_a_verdict ?? 0} verdict(s) in agent runs`, ShieldCheck, 'lime'), card('Service type', 'BACKEND', 'deterministic · recommends only', LockKeyhole, 'amber')]}</div>
        <div className="eyebrow" style={{ marginTop: 14 }}>Agent performance · from the existing agent_runs history only</div>
        <div className="table-wrap"><table className="data-table"><thead><tr><th>Agent</th><th>Runs</th><th>Successful</th><th>Failed</th><th>Partial</th><th>Avg time (s)</th></tr></thead><tbody>{Object.entries(perf?.agents ?? {}).map(([name, a]) => <tr key={name}><td>{name}</td><td className="mono">{a.total_runs}</td><td className="mono">{a.successful_runs}</td><td className="mono">{a.failed_runs}</td><td className="mono">{a.partial_runs}</td><td className="mono">{a.average_execution_time_seconds ?? '—'}</td></tr>)}</tbody></table></div>
      </>}
    </div></Panel>
    <div style={{ height: 14 }} />
    <Panel title="ML Threat Predictor" meta="ML PREDICTION ENGINE · NOT AN AUTONOMOUS AGENT"><div className="panel-body" data-testid="panel-ml-engine">
      {!ml ? <p className="mono muted">ML status is not available (backend unreachable).</p> : <>
        <div className="grid-4">{[card('Status', ml.available ? 'READY' : 'NO MODEL', ml.error ?? `${ml.kind}`, Bot, ml.available ? 'lime' : 'amber'), card('Active model', ml.active_version ?? '—', `${ml.versions} version(s) stored`, Cpu), card('Training data', ml.dataset_size ? String(ml.dataset_size.total) : '—', ml.data_source ?? 'simulator-generated', Database, 'cyan'), card('Authority', 'PREDICT ONLY', 'cannot create incidents or act', LockKeyhole, 'amber')]}</div>
        {metrics && <><div className="eyebrow" style={{ marginTop: 14 }}>Held-out evaluation · {metrics.evaluation_scope}</div>
          <div className="grid-4" style={{ marginTop: 8 }}>{[card('Accuracy', pct(metrics.metrics.accuracy), `${metrics.metrics.test_samples} test samples`, ShieldCheck), card('Threat precision', pct(metrics.metrics.threat_detection.precision), `${metrics.metrics.threat_detection.false_positives} false positive(s)`, AlertTriangle, 'amber'), card('Threat recall', pct(metrics.metrics.threat_detection.recall), `${metrics.metrics.threat_detection.false_negatives} false negative(s)`, ShieldAlert, 'lime'), card('Macro F1', pct(metrics.metrics.macro.f1), 'across 6 classes', Activity, 'cyan')]}</div>
          <p className="mono muted" style={{ margin: '10px 0 0' }} data-testid="ml-limitation">⚠ {metrics.limitations[0]} {metrics.limitations[1]}</p></>}
      </>}
    </div></Panel>
  </div>;
}

function IncidentDetail({ incidents, onAction, onToast, onRunTriage, onRunInvestigation, onRunCompliance, onRunRemediation, onDecideApproval, onRunVerification }: { incidents: Incident[]; onAction: (id: string, action: string) => void; onToast: (title: string, message: string) => void; onRunTriage: (incidentId: string) => Promise<TriageRunSummary | null>; onRunInvestigation: (incidentId: string) => Promise<InvestigationRunSummary | null>; onRunCompliance: (incidentId: string) => Promise<ComplianceRunSummary | null>; onRunRemediation: (incidentId: string) => Promise<RemediationRunSummary | null>; onDecideApproval: (approvalId: string, decision: 'approve' | 'reject' | 'execute') => Promise<void>; onRunVerification: (incidentId: string) => Promise<VerificationRunSummary | null> }) {
  const [triageRun, setTriageRun] = useState<TriageRunSummary | null>(null); const [triaging, setTriaging] = useState(false);
  const [invRun, setInvRun] = useState<InvestigationRunSummary | null>(null); const [investigating, setInvestigating] = useState(false);
  const [cmpRun, setCmpRun] = useState<ComplianceRunSummary | null>(null); const [assessing, setAssessing] = useState(false);
  const [remRun, setRemRun] = useState<RemediationRunSummary | null>(null); const [planning, setPlanning] = useState(false); const [deciding, setDeciding] = useState(false);
  const [verRun, setVerRun] = useState<VerificationRunSummary | null>(null); const [verifying, setVerifying] = useState(false);
  const { id } = useParams<{ id: string }>();
  const item = incidents.find(i => i.id === id);
  if (!item) return <div className="error-box">Incident not found. <Link href="/incidents" style={{ textDecoration: 'underline' }}>Return to queue</Link></div>;
  const d = item.detail; // present for real (backend) incidents only
  const demoTimeline = [
    ['14:32:18', 'Monitor signal created', 'GuardDuty observed an AttachUserPolicy call from a non-admin CI principal.'],
    ['14:32:22', 'Triage correlated identity chain', 'AssumeRole and policy attachment were linked to the same source session.'],
    ['14:33:11', 'Compliance confirmed escalation', 'Policy simulator reproduced administrative access with 99% confidence.'],
    ['14:34:03', 'Remediation plan proposed', 'Detach AdministratorAccess and invalidate active sessions. Human approval required.'],
  ].map(([time, title, copy], index) => ({ key: time, time: `${time}.0${index}`, title, copy }));
  const eventEvidence = d ? d.evidence.filter(e => e.kind === 'event').sort((a, b) => (a.timestamp ?? '').localeCompare(b.timestamp ?? '')) : [];
  const timeline = d ? eventEvidence.map(e => ({ key: e.id, time: (e.timestamp ?? '').replace('T', ' ').slice(11, 23), title: `${e.eventType} · ${e.source}`, copy: `${e.description}${e.indicators.length ? ` · signals: ${e.indicators.join(', ')}` : ''}` })) : demoTimeline;
  const demoSteps = ['Monitor Agent normalized 18 related events into one signal.', 'Triage Agent raised priority from high to critical.', 'Investigator Agent identified an unauthorized policy attachment.', 'Remediation Agent drafted reversible containment plan.']
    .map((text, i) => ({ text, time: `${['14:32:18', '14:32:22', '14:33:11', '14:34:03'][i]} · confidence ${item.confidence - i}%`, badge: i === 3 ? 'gated' : 'logged', kind: i === 3 ? 'review' : 'active', gated: i === 3 }));
  const pendingStages: [string, keyof NonNullable<typeof d>['stages']][] = [['Investigator Agent · investigation', 'investigation'], ['Compliance Agent · compliance findings', 'compliance'], ['Remediation Agent · remediation plan', 'remediation'], ['Remediation Agent · verification', 'verification']];
  const agentSteps = d ? [
    ...d.decisions.filter(dec => dec.actor === 'Monitor Agent').map(dec => ({ text: `${dec.actor}: ${dec.decision.replace(/_/g, ' ')} — ${dec.reasoning}`, time: `${dec.timestamp} · confidence ${dec.confidence}%`, badge: 'logged', kind: 'active', gated: false })),
    d.triage
      ? { text: `Triage Agent (${d.triage.method === 'llm' ? `${d.triage.model}` : 'rule-based fallback'}): ${d.triage.severity}/${d.triage.priority} → ${d.triage.nextStep} — ${d.triage.classification}`, time: `${d.triage.timestamp} · confidence ${d.triage.confidence}%`, badge: 'logged', kind: 'active', gated: false }
      : { text: 'Triage Agent · severity, priority & investigation decision', time: 'not run yet — use Run Triage Agent', badge: 'pending', kind: 'idle', gated: false },
    d.investigation
      ? { text: `Investigator Agent (${d.investigation.method === 'llm' ? d.investigation.model : 'rule-based fallback'}): ${d.investigation.findings.length} findings, ${d.investigation.mitre.filter(m => m.status === 'confirmed').length} confirmed MITRE → ${d.investigation.nextStep.replace(/_/g, ' ')}`, time: `${d.investigation.timestamp} · confidence ${d.investigation.confidence}%`, badge: 'logged', kind: 'active', gated: false }
      : { text: 'Investigator Agent · investigation', time: 'not run yet — use Run Investigation Agent', badge: 'pending', kind: 'idle', gated: false },
    d.compliance
      ? { text: `Compliance Agent (${d.compliance.method === 'llm' ? d.compliance.model : 'rule-based fallback'}): overall ${label(d.compliance.overallStatus)}; ${d.compliance.controls.length} controls, ${d.compliance.gaps.length} gaps, reporting ${label(d.compliance.reportingStatus)}`, time: `${d.compliance.timestamp} · confidence ${d.compliance.confidence}%`, badge: 'logged', kind: 'active', gated: false }
      : { text: 'Compliance Agent · compliance assessment', time: 'not run yet — use Run Compliance Agent', badge: 'pending', kind: 'idle', gated: false },
    d.remediation
      ? { text: `Remediation Agent (${d.remediation.method === 'llm' ? d.remediation.model : label(d.remediation.method)}): ${d.remediation.plan.action === 'no_action' ? 'no action proposed' : `${label(d.remediation.plan.action)} on ${d.remediation.plan.target}`} — ${label(d.remediation.execution.status)}`, time: `${d.remediation.timestamp} · confidence ${d.remediation.confidence}%`, badge: d.remediation.execution.status === 'executed' ? 'executed' : 'gated', kind: d.remediation.execution.status === 'executed' ? 'active' : 'review', gated: d.remediation.execution.status !== 'executed' }
      : { text: 'Remediation Agent · remediation plan', time: 'not run yet — use Run Remediation Agent', badge: 'pending', kind: 'idle', gated: false },
    d.verification
      ? { text: `Verification Agent (deterministic): ${label(d.verification.status)} — ${d.verification.comparison.map(c => `${c.field} expected ${showValue(c.expected)}, actual ${showValue(c.actual)}`).join('; ') || d.verification.reason}`, time: `${d.verification.timestamp} · confidence ${d.verification.confidence.toFixed(2)}`, badge: d.verification.status, kind: d.verification.status === 'verified' ? 'active' : 'critical', gated: false }
      : { text: 'Verification Agent · verification', time: 'not run yet — runs after the remediation executes', badge: 'pending', kind: 'idle', gated: false },
    ...pendingStages.filter(([, stage]) => stage !== 'investigation' && stage !== 'compliance' && stage !== 'remediation' && stage !== 'verification').map(([text, stage]) => ({ text, time: d.stages[stage] ? 'recorded' : 'not implemented yet', badge: d.stages[stage] ? 'recorded' : 'pending', kind: d.stages[stage] ? 'active' : 'idle', gated: stage === 'remediation' })),
  ] : demoSteps;
  const facts = d
    ? [['Affected resource', item.resource], ['Source IP', item.sourceIp], ['Principal', item.user], [d.triage ? 'Triage confidence' : 'Monitor confidence', `${item.confidence}%`], ['Category / priority', `${d.category.toUpperCase()} · ${d.priority ?? '—'}`], ['Current agent', item.currentAgent]]
    : [['Affected resource', item.resource], ['Source IP', item.sourceIp], ['Principal', item.user], ['Confidence', `${item.confidence}%`], ['Current agent', item.currentAgent], ['Case owner', 'A. Sharma']];
  const latestDecision = d?.decisions[d.decisions.length - 1];
  return <>
    <div style={{ marginBottom: 20 }}><Link href="/incidents" className="button ghost" data-testid="link-back-incidents"><ArrowLeft size={14} />Back to incidents</Link></div>
    <div className="detail-layout">
      <div className="detail-stack">
        <Panel>
          <div className="incident-hero">
            <div className="incident-id">{item.id} / {item.source.toUpperCase()}</div>
            <h1 className="incident-title">{item.title}</h1>
            <p className="page-subtitle" style={{ marginBottom: 14 }}>{item.description}</p>
            <div className="hero-meta"><Badge kind={item.severity}>{d && !d.triage ? 'initial ' : ''}{item.severity} severity</Badge><Badge kind={item.status === 'Awaiting approval' ? 'review' : 'active'}>{item.status}</Badge><span className="mono muted">Created {item.created}</span></div>
          </div>
          <div className="fact-grid">
            {facts.map(([label, value]) => <div className="fact" key={label}><span className="label">{label}</span><span className={`value ${label === 'Affected resource' || label === 'Source IP' || label === 'Principal' ? 'mono' : ''}`} style={label.endsWith('onfidence') ? { color: 'hsl(var(--secondary))' } : undefined}>{value}</span></div>)}
          </div>
        </Panel>
        <Panel title={d ? 'Event timeline' : 'Attack timeline'} meta={d ? `${timeline.length} CORRELATED EVENTS / MONITOR AGENT` : 'AUTONOMOUS INVESTIGATION'}>
          <div className="timeline">{timeline.map(entry => <div className="timeline-item" key={entry.key}><div className="timeline-time">{entry.time}</div><div className="timeline-rail"><div className="timeline-dot" /></div><div className="timeline-content"><strong>{entry.title}</strong><p>{entry.copy}</p></div></div>)}</div>
        </Panel>
        <Panel title="Agent activity" meta="DECISION TRACE">
          <div className="panel-body"><div className="agent-activity">{agentSteps.map(step => <div className="activity-item" key={step.text + step.time}><div className="activity-icon">{step.gated ? <LockKeyhole size={13} /> : <Bot size={13} />}</div><div className="activity-copy"><span>{step.text}</span><span className="time">{step.time}</span></div><Badge kind={step.kind}>{step.badge}</Badge></div>)}</div></div>
        </Panel>
        {d && <InvestigationPanel investigation={d.investigation} lastRun={invRun} running={investigating} triaged={d.triage !== null} onRun={async () => { setInvestigating(true); setInvRun(await onRunInvestigation(item.id)); setInvestigating(false); }} />}
        {d && <CompliancePanel compliance={d.compliance} investigationRunId={d.investigation?.runId ?? null} lastRun={cmpRun} running={assessing} investigated={d.investigation !== null} onRun={async () => { setAssessing(true); setCmpRun(await onRunCompliance(item.id)); setAssessing(false); }} />}
        {d && <RemediationPanel remediation={d.remediation} complianceRunId={d.compliance?.runId ?? null} lastRun={remRun} running={planning} assessed={d.compliance !== null && d.compliance.basedOnInvestigationRun === (d.investigation?.runId ?? null)} deciding={deciding} onRun={async () => { setPlanning(true); setRemRun(await onRunRemediation(item.id)); setPlanning(false); }} onDecide={async (approvalId, decision) => { setDeciding(true); await onDecideApproval(approvalId, decision); setDeciding(false); }} />}
        {d && <VerificationPanel verification={d.verification} remediation={d.remediation} lastRun={verRun} running={verifying} onRun={async () => { setVerifying(true); setVerRun(await onRunVerification(item.id)); setVerifying(false); }} />}
        {d && <FeedbackPanel incidentId={item.id} verification={d.verification} remediation={d.remediation} />}
      </div>
      <div className="detail-stack">
        {d && <MLPanel ml={d.ml} />}
        {d && <TriagePanel triage={d.triage} lastRun={triageRun} running={triaging} relatedEventIds={d.relatedEventIds} onRun={async () => { setTriaging(true); setTriageRun(await onRunTriage(item.id)); setTriaging(false); }} />}
        <Panel title="Response actions" meta={d ? 'AVAILABLE WITH LATER AGENTS' : undefined}>
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <button className="button primary" disabled={Boolean(d)} style={d ? { opacity: 0.45, cursor: "not-allowed" } : undefined} onClick={() => { onAction(item.id, 'Response plan submitted'); onToast('Action submitted', `${item.id} is now queued for the human approval gate.`); }} data-testid="button-submit-response"><Zap size={14} />Submit response plan</button>
            <button className="button" disabled={Boolean(d)} style={d ? { opacity: 0.45, cursor: "not-allowed" } : undefined} onClick={() => { onAction(item.id, 'Investigation rerun'); onToast('Investigation rerun', 'Fresh evidence collection has been queued.'); }} data-testid="button-rerun-investigation"><RefreshCw size={14} />Rerun investigation</button>
            <button className="button danger" disabled={Boolean(d)} style={d ? { opacity: 0.45, cursor: "not-allowed" } : undefined} onClick={() => onToast('Escalated to analyst', 'A high-priority analyst review has been requested.')} data-testid="button-escalate-incident"><AlertTriangle size={14} />Escalate to analyst</button>
            {d && <span className="mono muted">Response actions arrive with the Investigator and Remediation agents.</span>}
          </div>
        </Panel>
        {d ? <Panel title="Monitor classification" meta="INITIAL SIGNAL">
          <div className="panel-body"><div className="kv-list">{[['Category', (d.triage?.previous.category ?? d.category).toUpperCase()], ['Initial severity', d.triage?.previous.severity ?? item.severity], ['Initial priority', (d.triage ? d.triage.previous.priority : d.priority) ?? '—'], ['Trigger event', d.eventType], ['Account / region', `${d.accountId} · ${d.region}`], ['Related events', String(d.relatedEventIds.length)], ['Final prioritization', d.triage ? `Triage Agent · ${d.triage.severity}/${d.triage.priority}` : 'Triage Agent (not run yet)']].map(([key, value]) => <div className="kv" key={key}><span className="key">{key}</span><span className="val mono">{value}</span></div>)}</div></div>
        </Panel> : <Panel title="Threat intelligence" meta="ENRICHMENT">
          <div className="panel-body"><div className="kv-list">{[['IP reputation', 'Malicious · 87 reports'], ['MITRE technique', 'T1098 · Account Manipulation'], ['First observed', '2025-02-14 14:31:57'], ['Related incidents', '3 signals / 1 principal']].map(([key, value]) => <div className="kv" key={key}><span className="key">{key}</span><span className={`val ${key !== 'IP reputation' ? 'mono' : ''}`} style={key === 'IP reputation' ? { color: '#ff9a95' } : undefined}>{value}</span></div>)}</div></div>
        </Panel>}
        {d ? <Panel title="Evidence" meta={`${d.evidence.length} ARTIFACTS`}>
          <div className="panel-body"><div className="kv-list">{d.evidence.map(e => <div className="kv" key={e.id} title={e.description}><span className="key">{e.kind === 'event' ? <FileSearch size={13} style={{ verticalAlign: 'middle', marginRight: 7 }} /> : <Fingerprint size={13} style={{ verticalAlign: 'middle', marginRight: 7 }} />}{e.kind === 'event' ? e.eventType : 'Cloud state'}</span><span className="val mono" style={{ color: 'hsl(var(--accent))' }}>{e.eventId ? e.eventId.slice(0, 13) : e.description.replace('Simulated cloud state of ', '').replace(' when the Monitor ran', '')}</span></div>)}</div></div>
        </Panel> : <Panel title="Evidence" meta="4 ARTIFACTS">
          <div className="panel-body"><div className="kv-list">{[['CloudTrail event', 'evt_88291.json'], ['Policy diff', 'policy_diff.txt'], ['Session fingerprint', 'sha256:8b3a...e1c']].map(([key, value], i) => <div className="kv" key={key}><span className="key">{i === 0 ? <FileSearch size={13} style={{ verticalAlign: 'middle', marginRight: 7 }} /> : i === 1 ? <Code2 size={13} style={{ verticalAlign: 'middle', marginRight: 7 }} /> : <Fingerprint size={13} style={{ verticalAlign: 'middle', marginRight: 7 }} />}{key}</span><span className="val" style={{ color: 'hsl(var(--accent))' }}>{value}</span></div>)}</div></div>
        </Panel>}
        <Panel title="Agent reasoning" meta={d ? 'MONITOR OUTPUT' : 'COMPLIANCE OUTPUT'}>
          <div className="panel-body"><div className="code-block">{d ? JSON.stringify({ agent: latestDecision?.actor ?? 'Monitor Agent', decision: latestDecision?.decision, confidence: (latestDecision?.confidence ?? 0) / 100, reasoning: latestDecision?.reasoning, pending: ['triage', 'investigation', 'compliance', 'remediation', 'verification'] }, null, 2) : `{\n  "verdict": "confirmed",\n  "confidence": ${item.confidence / 100},\n  "blast_radius": "single_principal",\n  "reversible": true\n}`}</div></div>
        </Panel>
      </div>
    </div>
  </>;
}

function EventsPage({ events, onToast }: { events: SecurityEvent[]; onToast: (title: string, message: string) => void }) {
  const [query, setQuery] = useState(''); const [risk, setRisk] = useState('all'); const [sortDesc, setSortDesc] = useState(true);
  const visible = useMemo(() => [...events].filter(e => (`${e.id} ${e.type} ${e.user} ${e.resource} ${e.sourceIp}`.toLowerCase().includes(query.toLowerCase()) && (risk === 'all' || e.risk === risk))).sort((a, b) => sortDesc ? b.timestamp.localeCompare(a.timestamp) : a.timestamp.localeCompare(b.timestamp)), [events, query, risk, sortDesc]);
  const exportCsv = () => { const csv = ['id,timestamp,type,user,sourceIp,resource,risk', ...visible.map(e => [e.id,e.timestamp,e.type,e.user,e.sourceIp,e.resource,e.risk].join(','))].join('\\n'); const blob = new Blob([csv], { type: 'text/csv' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'agentsoc-events.csv'; a.click(); URL.revokeObjectURL(url); onToast('Export ready', `${visible.length} security events downloaded as CSV.`); };
  return <><PageHead eyebrow="Telemetry / normalized stream" title="Security Events" subtitle="Raw and correlated cloud activity across the simulated AWS account." actions={<button className="button" onClick={exportCsv} data-testid="button-export-events"><Download size={14} />Export CSV</button>} /><Panel title="Event stream" meta={`${visible.length} EVENTS`}><div className="filters"><div style={{ position: 'relative' }}><Search size={14} style={{ position: 'absolute', left: 10, top: 10, color: '#706e7e' }} /><input className="field search-field" style={{ paddingLeft: 31 }} placeholder="Search event, principal, resource..." value={query} onChange={e => setQuery(e.target.value)} data-testid="input-search-events" /></div><select className="field select-field" value={risk} onChange={e => setRisk(e.target.value)} data-testid="select-event-risk"><option value="all">All risk levels</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><button className="button ghost" onClick={() => setSortDesc(!sortDesc)} data-testid="button-sort-events">{sortDesc ? <ArrowDown size={14} /> : <ArrowUp size={14} />}Timestamp</button></div><div className="table-wrap"><table className="data-table"><thead><tr><th>Event / timestamp</th><th>Type</th><th>Principal</th><th>Source IP</th><th>Resource</th><th>Risk</th></tr></thead><tbody>{visible.map(event => <tr key={event.id}><td><div className="mono" style={{ color: 'hsl(var(--accent))' }}>{event.id}</div><div className="mono muted" style={{ marginTop: 4 }}>{event.timestamp}</div></td><td className="strong">{event.type}</td><td><div>{event.user}</div></td><td className="mono">{event.sourceIp}</td><td className="mono">{event.resource}</td><td><Badge kind={event.risk}>{event.risk}</Badge></td></tr>)}</tbody></table>{!visible.length && <div className="empty-state"><Activity size={24} /><strong>No events found</strong><span>Adjust the telemetry filters to see more activity.</span></div>}</div></Panel></>;
}

function AgentsPage({ agents, mode }: { agents: Agent[]; mode: DataMode }) {
  const live = mode === 'live'; const implemented = agents.filter(a => a.implemented).length;
  // live: Telemetry + implemented agents are real stages; the rest are not built yet
  const liveDone = (i: number) => i === 0 || Boolean(agents[i - 1]?.implemented);
  return <><PageHead eyebrow="Autonomy / six specialists" title="Agent Network" subtitle="The specialized reasoning layer that moves an incident from signal to controlled response." actions={<Badge kind="active">{live ? `${implemented} of ${agents.length} agents implemented` : `${agents.length} agents online`}</Badge>} /><div className="agent-grid">{agents.map(agent => <AgentCard key={agent.id} agent={agent} />)}</div>{live && <ServiceCards />}<div style={{ marginTop: 14 }}><Panel title="Pipeline contract" meta="INTER-AGENT HANDOFFS"><div className="pipeline">{['Telemetry', 'Monitor', 'Triage', 'Investigator', 'Compliance', 'Remediation'].map((step, i) => { const done = live ? liveDone(i) : i < 3; return <div className="pipeline-step" key={step}><div className={`pipeline-node ${done ? 'done' : !live && i === 3 ? 'current' : ''}`}>{done ? <Check size={15} /> : <GitBranch size={15} />}</div><div className="pipeline-label">{step}</div><div className="pipeline-detail">{live && !done ? 'not implemented' : i === 5 ? 'human gate' : 'structured JSON'}</div></div>; })}</div></Panel></div></>;
}
const agentBadgeKind = (status: Agent['status']) => (status === 'Active' || status === 'Ready' ? 'active' : 'idle');
function AgentCard({ agent }: { agent: Agent }) { return <Link href={`/agents/${agent.id}`} className="panel agent-card" data-testid={`card-agent-${agent.id}`}><div className="agent-card-head"><div style={{ display: 'flex', alignItems: 'center', gap: 11 }}><div className="agent-emblem"><Bot size={18} /></div><div><div className="agent-name">{agent.name}</div><div className="mono muted" style={{ marginTop: 4 }}>agent/{agent.id}</div></div></div><Badge kind={agentBadgeKind(agent.status)}>{agent.status}</Badge></div><p className="agent-purpose">{agent.purpose}</p><div className="tool-row">{agent.tools.map(tool => <span className="tool" key={tool}>{tool}</span>)}</div><div className="agent-foot"><span>{agent.stats ? (agent.id === 'triage' || agent.id === 'investigator' || agent.id === 'compliance' || agent.id === 'remediation' || agent.id === 'verification' ? `${agent.stats.runs} runs · ${agent.stats.successfulRuns ?? 0} ok · ${agent.stats.failedRuns ?? 0} failed` : `${(agent.stats.eventsProcessed ?? 0).toLocaleString()} events · ${agent.stats.incidentsCreated ?? 0} incidents`) : `${agent.tasks.toLocaleString()} tasks`}</span><span>{agent.lastActivity}</span></div></Link>; }

function AgentDetail({ agents, audit, mode }: { agents: Agent[]; audit: AuditEntry[]; mode: DataMode }) {
  const { id } = useParams<{ id: string }>(); const agent = agents.find(a => a.id === id); const live = mode === 'live';
  const decisions = live ? audit.filter(entry => entry.agent === agent?.name).slice(0, 5) : seedAudit.slice(0, 5);
  if (!agent) return <div className="error-box">Agent not found. <Link href="/agents" style={{ textDecoration: 'underline' }}>Return to network</Link></div>;
  const stats = agent.stats; const last = stats?.lastResult;
  const cards = !live
    ? <><StatCard label="Tasks processed" value={agent.tasks.toLocaleString()} meta="Last 24 hours" icon={Bot} /><StatCard label="Avg confidence" value="94.7%" meta="Across decisions" icon={ShieldCheck} accent="lime" /><StatCard label="Last activity" value="14s" meta={agent.lastActivity} icon={Activity} accent="cyan" /><StatCard label="Guardrail state" value="LOCKED" meta="Human gate enabled" icon={LockKeyhole} accent="amber" /></>
    : stats && agent.id === 'verification'
      ? <><StatCard label="Runs" value={String(stats.runs)} meta={`${stats.verified ?? 0} verified · ${stats.verificationFailed ?? 0} failed`} icon={Bot} /><StatCard label="Partial / unknown" value={`${stats.partial ?? 0} / ${stats.unknown ?? 0}`} meta={`${stats.skipped ?? 0} skipped`} icon={AlertTriangle} accent="amber" /><StatCard label="Last incident" value={stats.lastIncidentId ?? '—'} meta={last ? `${last.status} · ${last.outcome.replace(/_/g, ' ')}` : 'never run'} icon={ShieldAlert} accent="cyan" /><StatCard label="Method" value={(stats.method ?? 'deterministic').toUpperCase()} meta="read-only · no LLM · no action tools" icon={LockKeyhole} accent="lime" /></>
    : stats && agent.id === 'remediation'
      ? <><StatCard label="Runs" value={String(stats.runs)} meta={`${stats.successfulRuns ?? 0} successful · ${stats.failedRuns ?? 0} failed`} icon={Bot} /><StatCard label="Pending approvals" value={String(stats.pendingApprovals ?? 0)} meta={`${stats.executedActions ?? 0} executed action(s)`} icon={CheckCircle2} accent="lime" /><StatCard label="Last incident" value={stats.lastIncidentId ?? '—'} meta={last ? `${last.status} · ${last.outcome.replace(/_/g, ' ')}` : 'never run'} icon={ShieldAlert} accent="cyan" /><StatCard label="Model" value={agent.llm?.configured ? (agent.llm.model ?? '—') : 'NONE'} meta={agent.llm?.configured ? `${agent.llm.provider} · plans only · human approval + ToolExecutor` : (agent.llm?.error ?? 'LLM_PROVIDER=none')} icon={LockKeyhole} accent="amber" /></>
    : stats && (agent.id === 'triage' || agent.id === 'investigator' || agent.id === 'compliance')
      ? <><StatCard label="Runs" value={String(stats.runs)} meta={`${stats.successfulRuns ?? 0} successful · ${stats.failedRuns ?? 0} failed${stats.fallbackRuns ? ` · ${stats.fallbackRuns} rule-based` : ''}`} icon={Bot} /><StatCard label="Last incident" value={stats.lastIncidentId ?? '—'} meta={last ? `${last.status} · ${last.outcome.replace(/_/g, ' ')}` : 'never run'} icon={ShieldAlert} accent="lime" /><StatCard label="Last run" value={stats.lastRunAt ? stats.lastRunAt.slice(11) : '—'} meta={last ? `confidence ${last.confidence}%` : 'never run'} icon={Activity} accent="cyan" /><StatCard label="Model" value={agent.llm?.configured ? (agent.llm.model ?? '—') : 'NONE'} meta={agent.llm?.configured ? `${agent.llm.provider} · read-only · validated output` : (agent.llm?.error ?? 'LLM_PROVIDER=none')} icon={LockKeyhole} accent="amber" /></>
      : stats
      ? <><StatCard label="Events processed" value={(stats.eventsProcessed ?? 0).toLocaleString()} meta={`${stats.runs} runs · ${stats.duplicates} duplicates · ${stats.eventsRejected} rejected`} icon={Bot} /><StatCard label="Incidents" value={`${stats.incidentsCreated}`} meta={`created · ${stats.incidentsUpdated} updated`} icon={ShieldAlert} accent="lime" /><StatCard label="Last run" value={stats.lastRunAt ? stats.lastRunAt.slice(11) : '—'} meta={last ? `${last.status} · ${last.outcome.replace(/_/g, ' ')}` : 'never run'} icon={Activity} accent="cyan" /><StatCard label="Guardrail state" value="READ-ONLY" meta="No action tools · no LLM" icon={LockKeyhole} accent="amber" /></>
      : <><StatCard label="Tasks processed" value="0" meta="Not implemented yet" icon={Bot} /><StatCard label="Avg confidence" value="—" meta="No decisions yet" icon={ShieldCheck} accent="lime" /><StatCard label="Last activity" value="—" meta={agent.lastActivity} icon={Activity} accent="cyan" /><StatCard label="Guardrail state" value="LOCKED" meta="Human gate enabled" icon={LockKeyhole} accent="amber" /></>;
  const trace = live
    ? (last ? [last.summary, ...last.findings.slice(0, 6)] : [])
    : ['Received structured signal payload', 'Queried identity and asset graph', 'Compared against baseline behavior', 'Published handoff artifact'];
  return <><div style={{ marginBottom: 20 }}><Link href="/agents" className="button ghost" data-testid="link-back-agents"><ArrowLeft size={14} />Back to agents</Link></div><PageHead eyebrow={`Agent network / agent-${agent.id}`} title={agent.name} subtitle={agent.purpose} actions={<Badge kind={agentBadgeKind(agent.status)}>{agent.status}</Badge>} /><div className="grid-4">{cards}</div><div className="grid-2" style={{ marginTop: 14 }}><Panel title="Input / output contract" meta="SCHEMA V2"><div className="panel-body"><div className="eyebrow">INPUT</div><div className="code-block" style={{ margin: '8px 0 17px' }}>{`{\n  "source": "${agent.input}",\n  "trace_id": "tr_01HF9C",\n  "tenant": "acme-simulated"\n}`}</div><div className="eyebrow">OUTPUT</div><div className="code-block" style={{ marginTop: 8 }}>{live ? `{\n  "artifact": "${agent.output}",\n  "result": "AgentResult",\n  "next_handoff": "${agent.id === 'monitor' ? 'triage (explicit run)' : agent.id === 'triage' ? 'investigator (explicit run)' : agent.id === 'investigator' ? 'compliance (explicit run)' : agent.id === 'compliance' ? 'remediation (explicit run)' : agent.id === 'remediation' ? 'verification (explicit run)' : agent.id === 'verification' ? 'human review of the incident' : 'human_gate'}"\n}` : `{\n  "artifact": "${agent.output}",\n  "confidence": 0.947,\n  "next_handoff": "human_gate"\n}`}</div></div></Panel><Panel title="Tools & permissions" meta={`${agent.tools.length} INTEGRATIONS`}><div className="resource-list">{agent.tools.map((tool, i) => <div className="resource-row" key={tool}><div className="resource-icon">{i === 0 ? <Cloud size={15} /> : i === 1 ? <Database size={15} /> : <KeyRound size={15} />}</div><div className="resource-copy"><strong>{tool}</strong><span>Read-only connector · scoped to simulated account</span></div><Badge kind="active">enabled</Badge></div>)}</div></Panel></div><div className="grid-2" style={{ marginTop: 14 }}><Panel title="Recent decisions" meta="LAST 5"><div className="table-wrap"><table className="data-table"><thead><tr><th>Time</th><th>Incident</th><th>Decision</th><th>Confidence</th></tr></thead><tbody>{decisions.map(entry => <tr key={entry.id ?? entry.timestamp}><td className="mono muted">{entry.timestamp.slice(11)}</td><td className="mono" style={{ color: 'hsl(var(--primary))' }}>{entry.incidentId}</td><td>{entry.decision}</td><td className="mono">{entry.confidence === null ? '—' : `${entry.confidence}%`}</td></tr>)}</tbody></table></div></Panel><Panel title={live ? 'Last result' : 'Activity trace'} meta={live && last ? `CONFIDENCE ${last.confidence}%` : 'LIVE'}><div className="panel-body"><div className="agent-activity">{live && !trace.length && <div className="empty-state"><Bot size={24} /><strong>No activity yet</strong><span>{agent.implemented ? 'This agent has not run yet.' : 'This agent is not implemented yet.'}</span></div>}{trace.map((step, i) => <div className="activity-item" key={step}><div className="activity-icon"><Check size={13} /></div><div className="activity-copy"><span style={{ overflowWrap: 'anywhere' }}>{step}</span><span className="time">{live ? (i === 0 ? `${stats?.lastRunAt ?? ''} · reasoning summary` : 'finding') : `${i + 1}m ago · trace tr_01HF9C`}</span></div></div>)}</div></div></Panel></div></>;
}

function ApprovalsPage({ approvals, onDecision }: { approvals: Approval[]; onDecision: (approval: Approval, decision: 'Approved' | 'Rejected') => void }) {
  const [pending, setPending] = useState<{ approval: Approval; decision: 'Approved' | 'Rejected' } | null>(null);
  return <><PageHead eyebrow="Human gate / controlled response" title="Approval Center" subtitle="Autonomous agents can propose. An analyst always decides when a response changes the environment." actions={<Badge kind="review">{approvals.filter(a => a.status === 'Pending').length} pending decisions</Badge>} /><Panel title="Response proposals" meta="REQUIRES ANALYST DECISION"><div className="table-wrap"><table className="data-table"><thead><tr><th>Action</th><th>Incident</th><th>Resource</th><th>Requested by</th><th>Risk</th><th>Status</th><th>Decision</th></tr></thead><tbody>{approvals.map(approval => <tr key={approval.id}><td><div className="strong">{approval.action}</div><div className="mono muted" style={{ marginTop: 4 }}>{approval.id} · {approval.reason}</div></td><td><Link href={`/incidents/${approval.incidentId}`} className="mono" style={{ color: 'hsl(var(--primary))' }}>{approval.incidentId}</Link></td><td className="mono">{approval.resource}</td><td>{approval.requestedBy}</td><td><Badge kind={approval.risk}>{approval.risk}</Badge></td><td><Badge kind={approval.status === 'Pending' ? 'review' : approval.status === 'Approved' ? 'active' : 'critical'}>{approval.status}</Badge></td><td>{approval.status === 'Pending' ? <div style={{ display: 'flex', gap: 6 }}><button className="button lime" style={{ minHeight: 30, padding: '0 9px' }} onClick={() => setPending({ approval, decision: 'Approved' })} data-testid={`button-approve-${approval.id}`}><Check size={13} />Approve</button><button className="button danger" style={{ minHeight: 30, padding: '0 9px' }} onClick={() => setPending({ approval, decision: 'Rejected' })} data-testid={`button-reject-${approval.id}`}><X size={13} />Reject</button></div> : <span className="mono muted">Decision recorded</span>}</td></tr>)}</tbody></table></div></Panel><div className="grid-2" style={{ marginTop: 14 }}><Panel title="Guardrail policy" meta="ACTIVE"><div className="panel-body"><div className="kv-list">{[['Auto-execute', 'No destructive actions'], ['Approval timeout', 'Per remediation policy'], ['Evidence retention', '90 days'], ['Analyst quorum', '1 required']].map(([key, value]) => <div className="kv" key={key}><span className="key">{key}</span><span className="val">{value}</span></div>)}</div></div></Panel><Panel title="Decision principle" meta="REMEDIATION AGENT"><div className="panel-body"><p className="page-subtitle" style={{ margin: 0, lineHeight: 1.7 }}>Every proposal includes blast radius, reversibility, and confidence. The system defaults to preserve evidence first and contain second.</p></div></Panel></div>{pending && <ConfirmModal title={`${pending.decision} response proposal?`} body={<p className="page-subtitle" style={{ margin: 0 }}>You are about to <strong>{pending.decision.toLowerCase()}</strong> <span className="strong">{pending.approval.action}</span> on <span className="mono">{pending.approval.resource}</span>. This decision will be written to the immutable audit log.</p>} confirmLabel={`Confirm ${pending.decision.toLowerCase()}`} danger={pending.decision === 'Rejected'} onCancel={() => setPending(null)} onConfirm={() => { onDecision(pending.approval, pending.decision); setPending(null); }} />}</>;
}

function CloudPage({ cloud, onScan }: { cloud: CloudState; onScan: () => void }) {
  const [category, setCategory] = useState('all'); const categories = [...new Set(cloud.resources.map(r => r.category))]; const resources = cloud.resources.filter(r => category === 'all' || r.category === category);
  const summary = cloud.summary; const pad = (value: number) => String(value).padStart(2, '0');
  return <><PageHead eyebrow={summary ? 'Simulated AWS / live simulator state' : 'Simulated AWS / account 4821'} title="Cloud Environment" subtitle="Resource posture and blast-radius context for the current simulated tenant." actions={<button className="button ghost" onClick={onScan} data-testid="button-scan-cloud"><RefreshCw size={14} />Scan environment</button>} />{summary ? <div className="grid-4"><StatCard label="Resources tracked" value={pad(summary.total)} meta={`${categories.length} categories`} icon={Cloud} /><StatCard label="Healthy" value={pad(summary.healthy)} meta={`${summary.total ? (summary.healthy / summary.total * 100).toFixed(1) : '0'}% of inventory`} icon={ShieldCheck} accent="lime" /><StatCard label="At risk / exposed" value={pad(summary.at_risk + summary.exposed)} meta="Needs attention" icon={AlertTriangle} accent="amber" /><StatCard label="Isolated" value={pad(summary.isolated)} meta="Forensic hold" icon={Server} accent="cyan" /></div> : <div className="grid-4"><StatCard label="Resources tracked" value="42" meta="6 categories" icon={Cloud} /><StatCard label="Healthy" value="38" meta="90.4% of inventory" icon={ShieldCheck} accent="lime" /><StatCard label="At risk" value="02" meta="Needs attention" icon={AlertTriangle} accent="amber" /><StatCard label="Isolated" value="01" meta="Forensic hold" icon={Server} accent="cyan" /></div>}<div style={{ marginTop: 14 }}><Panel title="Resource inventory" meta={`${resources.length} VISIBLE RESOURCES`}><div className="filters"><button className={`mini-tab ${category === 'all' ? 'active' : ''}`} onClick={() => setCategory('all')} data-testid="button-filter-resource-all">All</button>{categories.map(item => <button key={item} className={`mini-tab ${category === item ? 'active' : ''}`} onClick={() => setCategory(item)} data-testid={`button-filter-resource-${item.toLowerCase()}`}>{item}</button>)}</div><div className="resource-list">{resources.map(resource => <div className="resource-row" key={resource.name}><div className="resource-icon">{resource.category === 'S3' ? <Database size={15} /> : resource.category === 'EC2' ? <Server size={15} /> : resource.category === 'IAM' ? <KeyRound size={15} /> : <Cloud size={15} />}</div><div className="resource-copy"><strong>{resource.name}</strong><span>{resource.category} · {resource.detail}</span></div><Badge kind={resource.status === 'Healthy' ? 'active' : resource.status === 'Exposed' ? 'critical' : resource.status === 'Isolated' ? 'review' : 'high'}>{resource.status}</Badge><ChevronRight size={14} color="#666375" /></div>)}</div></Panel></div></>;
}

function MonitorRunPanel({ scenario, monitor, monitorRunning, onRunMonitor, triageRun, triaging, onRunTriage, invRun, investigating, onRunInvestigation, cmpRun, assessing, onRunCompliance, incidentRemediation, remRun, planning, deciding, onRunRemediation, onDecideApproval, verRun, verifying, onRunVerification }: { scenario: ScenarioResult; monitor: MonitorRunSummary | null; monitorRunning: boolean; onRunMonitor: () => void; triageRun: TriageRunSummary | null; triaging: boolean; onRunTriage: (incidentId: string) => void; invRun: InvestigationRunSummary | null; investigating: boolean; onRunInvestigation: (incidentId: string) => void; cmpRun: ComplianceRunSummary | null; assessing: boolean; onRunCompliance: (incidentId: string) => void; incidentRemediation: (incidentId: string) => { remediation: RemediationInfo | null; complianceRunId: string | null; assessed: boolean; verification: VerificationInfo | null }; remRun: RemediationRunSummary | null; planning: boolean; deciding: boolean; onRunRemediation: (incidentId: string) => void; onDecideApproval: (approvalId: string, decision: 'approve' | 'reject' | 'execute') => void; verRun: VerificationRunSummary | null; verifying: boolean; onRunVerification: (incidentId: string) => void }) {
  const incidents = monitor ? [...monitor.incidentsCreated.map(id => [id, 'created']), ...monitor.incidentsUpdated.map(id => [id, 'updated'])] : [];
  return <>
    <div className="panel" style={{ marginTop: 14 }} data-testid="panel-simulation-result"><div className="panel-header"><div className="panel-title" style={{ color: 'hsl(var(--secondary))' }}><CheckCircle2 size={15} style={{ verticalAlign: 'middle', marginRight: 7 }} />Step 1 · Simulation completed</div><Badge kind="active">simulator</Badge></div><div className="panel-body"><div className="grid-3"><div><div className="eyebrow">Events generated</div><div className="stat-value" style={{ fontSize: 24 }}>{scenario.eventsGenerated}</div></div><div><div className="eyebrow">Scenario</div><div className="stat-value mono" style={{ fontSize: 14 }}>{scenario.scenario}</div></div><div><div className="eyebrow">Detection</div><div className="stat-value" style={{ fontSize: 16, color: '#858391' }}>{monitor ? 'Processed by Monitor' : 'Not processed yet'}</div></div></div><p className="page-subtitle" style={{ margin: '14px 0 0' }}>The simulator stored {scenario.eventsGenerated} events and changed the simulated cloud. It does not detect anything itself.</p></div></div>
    <div className="panel" style={{ marginTop: 14 }} data-testid="panel-monitor-result"><div className="panel-header"><div className="panel-title"><Bot size={15} style={{ verticalAlign: 'middle', marginRight: 7 }} />Step 2 · Monitor Agent processing</div>{monitor ? <Badge kind={monitor.status === 'success' ? 'active' : monitor.status === 'failed' ? 'critical' : 'review'}>{monitor.status} · {monitor.outcome.replace(/_/g, ' ')}</Badge> : <Badge kind="idle">not run</Badge>}</div><div className="panel-body">
      {!monitor && <button className="button primary" onClick={onRunMonitor} disabled={monitorRunning} data-testid="button-run-monitor">{monitorRunning ? <RefreshCw size={14} className="spin" /> : <Play size={14} />}Run Monitor Agent on these {scenario.eventIds.length} events</button>}
      {monitor && <><div className="grid-4"><div><div className="eyebrow">Events processed</div><div className="stat-value" style={{ fontSize: 24 }}>{monitor.processed}</div></div><div><div className="eyebrow">Correlated groups</div><div className="stat-value" style={{ fontSize: 24 }}>{monitor.groups.length}</div></div><div><div className="eyebrow">Duplicates / rejected</div><div className="stat-value" style={{ fontSize: 24 }}>{monitor.duplicates} / {monitor.rejected}</div></div><div><div className="eyebrow">Incidents</div>{incidents.length ? incidents.map(([id, how]) => <Link key={id} href={`/incidents/${id}`} className="stat-value" style={{ color: 'hsl(var(--primary))', fontSize: 16, display: 'block' }} data-testid={`link-monitor-incident-${id}`}>{id} <span className="mono muted" style={{ fontSize: 10 }}>{how}</span> <ExternalLink size={12} /></Link>) : <div className="stat-value" style={{ fontSize: 16, color: '#858391' }}>None</div>}</div></div>
        <div className="code-block" style={{ marginTop: 16 }}>{[`run_id: ${monitor.runId}`, `confidence: ${monitor.confidence}% (that this activity is an incident)`, `summary: ${monitor.summary}`, ...monitor.groups.map(g => `group ${g.id}: ${g.events} events by ${g.principal} -> ${g.decision}${g.indicators.length ? ` [${g.indicators.join(', ')}]` : ''}`), 'next: Triage Agent (run it explicitly in Step 3) - no other agent ran'].join('\n')}</div></>}
    </div></div>
    {monitor && incidents.length > 0 && <div style={{ marginTop: 14 }} data-testid="panel-simulator-triage">
      <div className="eyebrow" style={{ marginBottom: 8 }}>Step 3 · Triage Agent on {incidents[0][0]}</div>
      <TriagePanel triage={triageRun?.triage ?? null} lastRun={triageRun} running={triaging} relatedEventIds={[]} onRun={() => onRunTriage(incidents[0][0])} />
    </div>}
    {monitor && incidents.length > 0 && <div style={{ marginTop: 14 }} data-testid="panel-simulator-investigation">
      <div className="eyebrow" style={{ marginBottom: 8 }}>Step 4 · Investigator Agent on {incidents[0][0]}</div>
      <InvestigationPanel investigation={invRun?.investigation ?? null} lastRun={invRun} running={investigating} triaged={Boolean(triageRun?.triage)} onRun={() => onRunInvestigation(incidents[0][0])} />
    </div>}
    {monitor && incidents.length > 0 && <div style={{ marginTop: 14 }} data-testid="panel-simulator-compliance">
      <div className="eyebrow" style={{ marginBottom: 8 }}>Step 5 · Compliance Agent on {incidents[0][0]}</div>
      <CompliancePanel compliance={cmpRun?.compliance ?? null} investigationRunId={invRun?.investigation?.runId ?? null} lastRun={cmpRun} running={assessing} investigated={Boolean(invRun?.investigation)} onRun={() => onRunCompliance(incidents[0][0])} />
    </div>}
    {monitor && incidents.length > 0 && (() => { const live = incidentRemediation(incidents[0][0]); return <div style={{ marginTop: 14 }} data-testid="panel-simulator-remediation">
      <div className="eyebrow" style={{ marginBottom: 8 }}>Step 6 · Remediation Agent on {incidents[0][0]} · plan → approval → execution</div>
      <RemediationPanel remediation={live.remediation} complianceRunId={live.complianceRunId} lastRun={remRun} running={planning} assessed={live.assessed} deciding={deciding} onRun={() => onRunRemediation(incidents[0][0])} onDecide={onDecideApproval} />
    </div>; })()}
    {monitor && incidents.length > 0 && (() => { const live = incidentRemediation(incidents[0][0]); return <div style={{ marginTop: 14 }} data-testid="panel-simulator-verification">
      <div className="eyebrow" style={{ marginBottom: 8 }}>Step 7 · Verification Agent on {incidents[0][0]} · execution result → verification → incident status</div>
      <div className="mono muted" style={{ marginBottom: 8 }} data-testid="simulator-verification-summary">Remediation execution: {live.remediation ? label(live.remediation.execution.status) : 'not run'} · Verification: {live.verification ? label(live.verification.status) : 'not run'}</div>
      <VerificationPanel verification={live.verification} remediation={live.remediation} lastRun={verRun} running={verifying} onRun={() => onRunVerification(incidents[0][0])} />
      <div style={{ marginTop: 14 }} data-testid="panel-simulator-feedback"><div className="eyebrow" style={{ marginBottom: 8 }}>Step 8 · Feedback &amp; Learning on {incidents[0][0]} · outcome → failure analysis → recommendation → retry request</div><FeedbackPanel incidentId={incidents[0][0]} verification={live.verification} remediation={live.remediation} /></div>
    </div>; })()}
  </>;
}

function SimulatorPage({ mode, onSimulate, onReset, onRunMonitor, onRunTriage, onRunInvestigation, onRunCompliance, incidents, onRunRemediation, onDecideApproval, onRunVerification }: { mode: DataMode; incidents: Incident[]; onSimulate: (scenario: string) => Promise<ScenarioResult | null>; onReset: () => void; onRunMonitor: (eventIds: string[]) => Promise<MonitorRunSummary | null>; onRunTriage: (incidentId: string) => Promise<TriageRunSummary | null>; onRunInvestigation: (incidentId: string) => Promise<InvestigationRunSummary | null>; onRunCompliance: (incidentId: string) => Promise<ComplianceRunSummary | null>; onRunRemediation: (incidentId: string) => Promise<RemediationRunSummary | null>; onDecideApproval: (approvalId: string, decision: 'approve' | 'reject' | 'execute') => Promise<void>; onRunVerification: (incidentId: string) => Promise<VerificationRunSummary | null> }) {
  const [running, setRunning] = useState<string | null>(null); const [done, setDone] = useState<string | null>(null); const [result, setResult] = useState<ScenarioResult | null>(null);
  const [monitor, setMonitor] = useState<MonitorRunSummary | null>(null); const [monitorRunning, setMonitorRunning] = useState(false);
  const [triageRun, setTriageRun] = useState<TriageRunSummary | null>(null); const [triaging, setTriaging] = useState(false);
  const [invRun, setInvRun] = useState<InvestigationRunSummary | null>(null); const [investigating, setInvestigating] = useState(false);
  const [cmpRun, setCmpRun] = useState<ComplianceRunSummary | null>(null); const [assessing, setAssessing] = useState(false);
  const runComplianceStep = async (incidentId: string) => { setAssessing(true); setCmpRun(await onRunCompliance(incidentId)); setAssessing(false); };
  const [remRun, setRemRun] = useState<RemediationRunSummary | null>(null); const [planning, setPlanning] = useState(false); const [deciding, setDeciding] = useState(false);
  const runRemediationStep = async (incidentId: string) => { setPlanning(true); setRemRun(await onRunRemediation(incidentId)); setPlanning(false); };
  const decideStep = async (approvalId: string, decision: 'approve' | 'reject' | 'execute') => { setDeciding(true); await onDecideApproval(approvalId, decision); setDeciding(false); };
  const [verRun, setVerRun] = useState<VerificationRunSummary | null>(null); const [verifying, setVerifying] = useState(false);
  const runVerificationStep = async (incidentId: string) => { setVerifying(true); setVerRun(await onRunVerification(incidentId)); setVerifying(false); };
  const incidentRemediation = (incidentId: string) => { const detail = incidents.find(i => i.id === incidentId)?.detail; return { remediation: detail?.remediation ?? null, complianceRunId: detail?.compliance?.runId ?? null, assessed: Boolean(detail?.compliance) && detail?.compliance?.basedOnInvestigationRun === (detail?.investigation?.runId ?? null), verification: detail?.verification ?? null }; };
  const runInvestigationStep = async (incidentId: string) => { setInvestigating(true); setInvRun(await onRunInvestigation(incidentId)); setInvestigating(false); };
  const runTriageStep = async (incidentId: string) => { setTriaging(true); setTriageRun(await onRunTriage(incidentId)); setTriaging(false); };
  const live = mode === 'live';
  const scenarios = [['iam', 'IAM privilege escalation', 'Attach admin policy to a non-admin CI principal.'], ['s3', 'Public S3 exposure', 'Open a production export bucket to anonymous reads.'], ['ec2', 'EC2 command & control', 'Send a workload beacon to a known C2 destination.'], ['cred', 'Credential misuse', 'Reuse valid credentials from an unusual IP to read sensitive data.']];
  const run = async (id: string) => { setRunning(id); setDone(null); setResult(null); setMonitor(null); setTriageRun(null); setInvRun(null); setCmpRun(null); setRemRun(null); setVerRun(null); const outcome = await onSimulate(id); setRunning(null); if (outcome) { setResult(outcome); setDone(id); } };
  const runMonitorStep = async () => { if (!result) return; setMonitorRunning(true); const summary = await onRunMonitor(result.eventIds); setMonitorRunning(false); if (summary) setMonitor(summary); };
  return <><PageHead eyebrow="Simulation lab / no production impact" title="Attack Simulator" subtitle="Generate realistic AWS attack paths to exercise the autonomous response pipeline." actions={<div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><button className="button ghost" onClick={() => { setDone(null); setResult(null); setMonitor(null); onReset(); }} disabled={Boolean(running)} data-testid="button-reset-simulation"><RefreshCw size={14} />Reset environment</button><Badge kind="active">sandbox only</Badge></div>} /><Panel title="Scenario catalog" meta="SELECT A THREAT PATH"><div className="panel-body"><div className="scenario-grid">{scenarios.map(([id, title, copy]) => <button className="scenario" key={id} onClick={() => run(id)} disabled={Boolean(running)} data-testid={`button-scenario-${id}`}><div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}><strong>{title}</strong>{running === id ? <RefreshCw size={14} className="spin" /> : done === id ? <CheckCircle2 size={14} color="hsl(var(--secondary))" /> : <Play size={13} color="hsl(var(--primary))" />}</div><p>{copy}</p></button>)}</div></div></Panel>{running && <div className="panel" style={{ marginTop: 14, padding: 20 }}><div className="eyebrow">Executing scenario / {running.toUpperCase()}</div><div className="loading-skeleton" style={{ minHeight: 75, marginTop: 13 }} /></div>}{done && result && live && <MonitorRunPanel scenario={result} monitor={monitor} monitorRunning={monitorRunning} onRunMonitor={runMonitorStep} triageRun={triageRun} triaging={triaging} onRunTriage={runTriageStep} invRun={invRun} investigating={investigating} onRunInvestigation={runInvestigationStep} cmpRun={cmpRun} assessing={assessing} onRunCompliance={runComplianceStep} incidentRemediation={incidentRemediation} remRun={remRun} planning={planning} deciding={deciding} onRunRemediation={runRemediationStep} onDecideApproval={decideStep} verRun={verRun} verifying={verifying} onRunVerification={runVerificationStep} />}{done && !live && <div className="panel" style={{ marginTop: 14 }}><div className="panel-header"><div className="panel-title" style={{ color: 'hsl(var(--secondary))' }}><CheckCircle2 size={15} style={{ verticalAlign: 'middle', marginRight: 7 }} />Scenario completed successfully</div><Badge kind="active">events generated</Badge></div><div className="panel-body"><div className="grid-3"><div><div className="eyebrow">Events emitted</div><div className="stat-value" style={{ fontSize: 24 }}>{result?.eventsGenerated ?? 0}</div></div><div><div className="eyebrow">Detection latency</div><div className="stat-value" style={{ fontSize: 24 }}>4.2s</div></div><div><div className="eyebrow">New incident</div><Link href="/incidents/INC-005" className="stat-value" style={{ color: 'hsl(var(--primary))', fontSize: 20 }}>INC-005 <ExternalLink size={13} /></Link></div></div><div className="code-block" style={{ marginTop: 16 }}>trace_id: sim_{Date.now().toString(36)}{'\n'}pipeline: monitor → triage → investigator → compliance → remediation{'\n'}status: incident created / approval gate armed (demo data)</div></div></div>}</>;
}

function AnalyticsPage() {
  const [range, setRange] = useState('7d'); const data = [{ d:'08', value:24 }, { d:'09', value:31 }, { d:'10', value:26 }, { d:'11', value:42 }, { d:'12', value:35 }, { d:'13', value:48 }, { d:'14', value:57 }];
  return <><PageHead eyebrow="Observability / demo data" title="Analytics" subtitle="Operational patterns across the simulated environment. Metrics are illustrative, not production telemetry." actions={<div className="mini-tabs">{['24h','7d','30d'].map(item => <button className={`mini-tab ${range === item ? 'active' : ''}`} onClick={() => setRange(item)} key={item} data-testid={`button-analytics-${item}`}>{item}</button>)}</div>} /><div className="panel" style={{ marginBottom: 14 }}><div className="panel-header"><div className="panel-title">Detections over time <small>DEMO DATA · {range}</small></div><Badge kind="active">synthetic</Badge></div><div className="activity-chart" style={{ height: 285, paddingTop: 20 }}><ResponsiveContainer width="100%" height="100%"><AreaChart data={data}><CartesianGrid stroke="#282633" vertical={false} /><XAxis dataKey="d" tick={{ fill: '#777586', fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis tick={{ fill: '#777586', fontSize: 10 }} axisLine={false} tickLine={false} /><Area type="monotone" dataKey="value" stroke="#47dae1" fill="rgba(71,218,225,.09)" strokeWidth={2} /><ChartTooltip contentStyle={{ background: '#191824', border: '1px solid #4a3850', fontSize: 11 }} /></AreaChart></ResponsiveContainer></div></div><div className="grid-3"><Panel title="Mean time to detect" meta="DEMO"><div className="panel-body"><div className="stat-value">4.2s</div><p className="page-subtitle">↓ 1.8s from baseline</p></div></Panel><Panel title="Mean time to contain" meta="DEMO"><div className="panel-body"><div className="stat-value">12m</div><p className="page-subtitle">With human approval gate</p></div></Panel><Panel title="False positive rate" meta="DEMO"><div className="panel-body"><div className="stat-value">3.8%</div><p className="page-subtitle">↓ 0.6% after correlation</p></div></Panel></div><div style={{ marginTop: 14 }}><Panel title="Detection coverage" meta="DEMO DATA"><div className="panel-body"><div className="heatmap">{Array.from({ length: 90 }, (_, i) => <span className={`heat-cell ${i % 13 === 0 ? 'l4' : i % 7 === 0 ? 'l3' : i % 3 === 0 ? 'l2' : i % 2 === 0 ? 'l1' : ''}`} key={i} />)}</div><div className="legend-row"><span>lower signal</span>{['', 'l1', 'l2', 'l3', 'l4'].map(level => <span className="legend-swatch" key={level} style={{ background: level ? undefined : '#242230' }} />)}<span>higher signal</span></div></div></Panel></div></>;
}

function AuditPage({ audit }: { audit: AuditEntry[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  return <><PageHead eyebrow="Accountability / immutable trace" title="Audit Log" subtitle="Every agent decision, handoff, and human gate recorded with its reasoning context." actions={<button className="button" data-testid="button-export-audit"><Download size={14} />Export log</button>} /><Panel title="Decision history" meta={`${audit.length} ENTRIES`}><div>{audit.map(entry => { const key = entry.id ?? entry.timestamp; return <div key={key} style={{ borderBottom: '1px solid #292634' }}><button style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%', textAlign: 'left', padding: '15px 16px', background: 'transparent', border: 0, color: 'inherit' }} onClick={() => setExpanded(expanded === key ? null : key)} data-testid={`button-expand-audit-${key}`}><ChevronRight size={14} style={{ transform: expanded === key ? 'rotate(90deg)' : undefined, transition: 'transform .16s ease' }} /><span className="mono muted" style={{ width: 132 }}>{entry.timestamp}</span><span style={{ width: 135 }} className="mono">{entry.agent}</span><span style={{ flex: 1 }}><span className="strong">{entry.action}</span><span className="muted"> · {entry.result}</span></span><Badge kind={entry.decision === 'Escalated' ? 'review' : 'active'}>{entry.decision}</Badge></button>{expanded === key && <div style={{ margin: '0 46px 17px', padding: 14, background: '#0d0d14', border: '1px solid #292735' }}><div className="grid-3"><div><div className="eyebrow">Input</div><div className="mono" style={{ marginTop: 6, overflowWrap: 'anywhere' }}>{entry.input}</div></div><div><div className="eyebrow">Reasoning</div><div className="mono" style={{ marginTop: 6 }}>{entry.reason}</div></div><div><div className="eyebrow">Confidence</div><div className="mono" style={{ color: 'hsl(var(--secondary))', marginTop: 6 }}>{entry.confidence === null ? '—' : `${entry.confidence}%`}</div></div></div></div>}</div>; })}</div></Panel></>;
}

function NotFound() { return <div className="empty-state"><AlertCircle size={30} /><strong>Route not found</strong><span><Link href="/" style={{ color: 'hsl(var(--primary))' }}>Return to SOC overview</Link></span></div>; }

function RouterContent(props: { data: DashboardData; onToast: (title: string, message: string) => void; onAction: (id: string, action: string) => void; onDecision: (approval: Approval, decision: 'Approved' | 'Rejected') => void; onSimulate: (scenario: string) => Promise<ScenarioResult | null>; onRunMonitor: (eventIds: string[]) => Promise<MonitorRunSummary | null>; onRunTriage: (incidentId: string) => Promise<TriageRunSummary | null>; onRunInvestigation: (incidentId: string) => Promise<InvestigationRunSummary | null>; onRunCompliance: (incidentId: string) => Promise<ComplianceRunSummary | null>; onRunRemediation: (incidentId: string) => Promise<RemediationRunSummary | null>; onDecideApproval: (approvalId: string, decision: 'approve' | 'reject' | 'execute') => Promise<void>; onRunVerification: (incidentId: string) => Promise<VerificationRunSummary | null>; onReset: () => void; onRefresh: () => void }) {
  const [, setLocation] = useLocation();
  const { data } = props;
  // Route children (not `component={() => ...}`) so pages keep their state when data reloads.
  return <Switch><Route path="/"><Overview incidents={data.incidents} agents={data.agents} stats={data.stats} mode={data.mode} goSimulator={() => setLocation('/simulator')} /></Route><Route path="/incidents"><IncidentsPage incidents={data.incidents} /></Route><Route path="/incidents/:id"><IncidentDetail incidents={data.incidents} onAction={props.onAction} onToast={props.onToast} onRunTriage={props.onRunTriage} onRunInvestigation={props.onRunInvestigation} onRunCompliance={props.onRunCompliance} onRunRemediation={props.onRunRemediation} onDecideApproval={props.onDecideApproval} onRunVerification={props.onRunVerification} /></Route><Route path="/events"><EventsPage events={data.events} onToast={props.onToast} /></Route><Route path="/agents"><AgentsPage agents={data.agents} mode={data.mode} /></Route><Route path="/agents/:id"><AgentDetail agents={data.agents} audit={data.audit} mode={data.mode} /></Route><Route path="/approvals"><ApprovalsPage approvals={data.approvals} onDecision={props.onDecision} /></Route><Route path="/cloud"><CloudPage cloud={data.cloud} onScan={props.onRefresh} /></Route><Route path="/simulator"><SimulatorPage mode={data.mode} incidents={data.incidents} onSimulate={props.onSimulate} onReset={props.onReset} onRunMonitor={props.onRunMonitor} onRunTriage={props.onRunTriage} onRunInvestigation={props.onRunInvestigation} onRunCompliance={props.onRunCompliance} onRunRemediation={props.onRunRemediation} onDecideApproval={props.onDecideApproval} onRunVerification={props.onRunVerification} /></Route><Route path="/analytics" component={AnalyticsPage} /><Route path="/audit"><AuditPage audit={data.audit} /></Route><Route component={NotFound} /></Switch>;
}

const wait = (ms: number) => new Promise(resolve => window.setTimeout(resolve, ms));

function App() {
  // Starts with the bundled demo data, then switches to the backend if it is reachable.
  const [data, setData] = useState<DashboardData>(demoData);
  const [toast, setToast] = useState<{ title: string; message: string } | null>(null);
  const [refreshTick, setRefreshTick] = useState(1);
  const [loading, setLoading] = useState(true);
  const [fadingOut, setFadingOut] = useState(false);
  const [initError, setInitError] = useState<string | null>(null);
  const [statusText, setStatusText] = useState('INITIALIZING SECURITY OPERATIONS...');

  const setIncidents = (update: (items: Incident[]) => Incident[]) => setData(current => ({ ...current, incidents: update(current.incidents) }));
  const setEvents = (update: (items: SecurityEvent[]) => SecurityEvent[]) => setData(current => ({ ...current, events: update(current.events) }));
  const setApprovals = (update: (items: Approval[]) => Approval[]) => setData(current => ({ ...current, approvals: update(current.approvals) }));
  const setAudit = (update: (items: AuditEntry[]) => AuditEntry[]) => setData(current => ({ ...current, audit: update(current.audit) }));
  const notify = useCallback((title: string, message: string) => { setToast({ title, message }); window.setTimeout(() => setToast(null), 4000); }, []);
  const reload = useCallback(async () => { const next = await loadDashboard(); setData(next); return next; }, []);

  const dismissLoading = useCallback(() => {
    setFadingOut(true);
    window.setTimeout(() => {
      setLoading(false);
    }, 500);
  }, []);

  const initialize = useCallback(async () => {
    setInitError(null);
    setStatusText('INITIALIZING SECURITY OPERATIONS...');
    const start = Date.now();
    try {
      const next = await loadDashboard();
      setData(next);
      const elapsed = Date.now() - start;
      const minDisplayMs = 1300;
      if (elapsed < minDisplayMs) {
        await wait(minDisplayMs - elapsed);
      }
      const forceDemo = import.meta.env.VITE_DEMO_MODE === 'true';
      if (next.mode === 'live' || forceDemo) {
        dismissLoading();
      } else {
        setInitError('Backend service offline at http://127.0.0.1:8000. Start the FastAPI backend or launch in demo mode.');
      }
    } catch {
      setInitError('Failed to establish connection to security operations backend.');
    }
  }, [dismissLoading]);

  useEffect(() => {
    void initialize();
  }, [initialize]);
  const onRefresh = async () => { const next = await reload(); setRefreshTick(value => value + 1); notify('Environment synced', next.mode === 'live' ? 'Events, cloud state and agents reloaded from the backend.' : 'Backend unreachable: showing demo telemetry and agent state.'); };
  const onReset = async () => { if (data.mode !== 'live') { notify('Environment reset', 'Demo mode: nothing to reset.'); return; } try { await resetEnvironment(); await reload(); notify('Environment reset', 'Simulated cloud restored. Event history is kept.'); } catch { notify('Reset failed', 'The backend could not reset the simulated cloud.'); } };
  const onAction = (id: string, action: string) => { setIncidents(items => items.map(item => item.id === id ? { ...item, currentAgent: 'Remediation Agent', status: 'Awaiting approval' } : item)); setAudit(items => [{ timestamp: new Date().toISOString().slice(0, 19).replace('T', ' '), agent: 'Remediation Agent', action, decision: 'Escalated', result: 'Awaiting human approval', incidentId: id, input: 'Analyst-triggered action', reason: 'Manual action from incident detail', confidence: 96 }, ...items]); };
  const onDecision = async (approval: Approval, decision: 'Approved' | 'Rejected') => { if (data.mode === 'live') { await onDecideApproval(approval.id, decision === 'Approved' ? 'approve' : 'reject'); return; } setApprovals(items => items.map(item => item.id === approval.id ? { ...item, status: decision } : item)); setAudit(items => [{ timestamp: new Date().toISOString().slice(0, 19).replace('T', ' '), agent: 'A. Sharma', action: approval.action, decision, result: decision === 'Approved' ? 'Response action executed' : 'Proposal rejected', incidentId: approval.incidentId, input: approval.reason, reason: 'Human analyst decision', confidence: 100 }, ...items]); notify(`Approval ${decision.toLowerCase()}`, `${approval.action} has been recorded in the audit log.`); };
  const onSimulate = async (scenario: string): Promise<ScenarioResult | null> => {
    if (data.mode === 'live') {
      try { const result = await runScenario(scenario); await reload(); notify('Scenario completed', `${result.eventsGenerated} events stored. Run the Monitor Agent to process them.`); return result; }
      catch { notify('Scenario failed', 'The backend could not run the scenario. No data was changed.'); return null; }
    }
    await wait(1300); onSimulateDemo(scenario); return { scenario, eventsGenerated: 18, eventIds: [], incidentId: 'INC-005' };
  };
  const onRunTriage = async (incidentId: string): Promise<TriageRunSummary | null> => {
    try {
      const summary = await runTriage(incidentId); await reload();
      if (summary.triage) notify('Triage Agent finished', `${incidentId}: ${summary.triage.severity}/${summary.triage.priority} → ${summary.triage.nextStep} (${summary.triage.method === 'llm' ? summary.triage.model : 'rule-based fallback'}).`);
      else notify('Triage failed', `${incidentId}: ${summary.outcome.replace(/_/g, ' ')}. The incident was not changed.`);
      return summary;
    } catch { notify('Triage failed', 'The backend did not answer. The incident was not changed.'); return null; }
  };
  const onRunInvestigation = async (incidentId: string): Promise<InvestigationRunSummary | null> => {
    try {
      const summary = await runInvestigation(incidentId); await reload();
      const inv = summary.investigation;
      if (inv) notify('Investigator Agent finished', `${incidentId}: ${inv.findings.length} findings, ${inv.mitre.filter(m => m.status === 'confirmed').length} confirmed MITRE technique(s) → ${inv.nextStep.replace(/_/g, ' ')} (${inv.method === 'llm' ? inv.model : 'rule-based fallback'}).`);
      else notify(summary.status === 'skipped' ? 'Investigation skipped' : 'Investigation failed', `${incidentId}: ${summary.outcome.replace(/_/g, ' ')}. The incident was not changed.`);
      return summary;
    } catch { notify('Investigation failed', 'The backend did not answer. The incident was not changed.'); return null; }
  };
  const onRunCompliance = async (incidentId: string): Promise<ComplianceRunSummary | null> => {
    try {
      const summary = await runCompliance(incidentId); await reload();
      const c = summary.compliance;
      if (c) notify('Compliance Agent finished', `${incidentId}: overall ${label(c.overallStatus)}; ${c.controls.length} controls, ${c.gaps.length} gaps, reporting ${label(c.reportingStatus)} (${c.method === 'llm' ? c.model : 'rule-based fallback'}).`);
      else notify(summary.status === 'skipped' ? 'Compliance assessment skipped' : 'Compliance assessment failed', `${incidentId}: ${label(summary.outcome)}. The incident was not changed.`);
      return summary;
    } catch { notify('Compliance assessment failed', 'The backend did not answer. The incident was not changed.'); return null; }
  };
  const onRunRemediation = async (incidentId: string): Promise<RemediationRunSummary | null> => {
    try {
      const summary = await runRemediation(incidentId); await reload();
      if (summary.status === 'success') notify('Remediation Agent finished', summary.outcome === 'no_action' ? `${incidentId}: no action proposed. Nothing changed.` : `${incidentId}: remediation proposed (${summary.method === 'llm' ? summary.model : 'rule-based fallback'}). Human approval is required; nothing was executed.`);
      else notify(summary.status === 'skipped' ? 'Remediation planning skipped' : 'Remediation planning failed', `${incidentId}: ${label(summary.outcome)}. No approval was created and nothing was changed.`);
      return summary;
    } catch { notify('Remediation planning failed', 'The backend did not answer. Nothing was changed.'); return null; }
  };
  const onDecideApproval = async (approvalId: string, decision: 'approve' | 'reject' | 'execute'): Promise<void> => {
    const result = await decideApproval(approvalId, decision); await reload();
    const text = DECISION_TEXT[result.outcome] ?? result.message;
    notify(result.ok ? (result.outcome === 'executed' ? 'Remediation executed' : decision === 'reject' ? 'Proposal rejected' : 'Approval recorded') : 'Decision not applied', text);
  };
  const onRunVerification = async (incidentId: string): Promise<VerificationRunSummary | null> => {
    try {
      const summary = await runVerification(incidentId); await reload();
      if (summary.status === 'skipped') notify('Verification skipped', `${incidentId}: ${label(summary.outcome)}. Nothing was read or changed.`);
      else if (summary.status === 'failed') notify('Verification failed to run', `${incidentId}: ${label(summary.outcome)}.`);
      else notify(summary.verificationStatus === 'verified' ? 'Remediation verified' : 'Verification: ' + label(summary.verificationStatus ?? 'unknown'), `${incidentId}: ${summary.verificationStatus === 'verified' ? 'the cloud state confirms the expected security effect.' : 'the expected security state was not confirmed. Nothing was retried; the incident stays open.'}`);
      return summary;
    } catch { notify('Verification failed', 'The backend did not answer. Nothing was changed.'); return null; }
  };
  const onRunMonitor = async (eventIds: string[]): Promise<MonitorRunSummary | null> => {
    try {
      const summary = await runMonitor(eventIds); await reload();
      const touched = summary.incidentsCreated.length + summary.incidentsUpdated.length;
      notify('Monitor Agent finished', `${summary.processed} events processed · ${touched ? `${summary.incidentsCreated.length} incident(s) created, ${summary.incidentsUpdated.length} updated` : 'no incident'}.`);
      return summary;
    } catch { notify('Monitor Agent failed', 'The backend could not run the Monitor Agent.'); return null; }
  };
  const onSimulateDemo = (scenario: string) => { const title = scenario === 'iam' ? 'Simulated IAM privilege escalation' : scenario === 's3' ? 'Simulated public S3 exposure' : scenario === 'cred' ? 'Simulated credential misuse' : 'Simulated EC2 command & control'; const newIncident: Incident = { id: 'INC-005', title, severity: 'high', source: 'Attack Simulator', resource: scenario === 's3' ? 's3://sim-prod-exports' : scenario === 'ec2' ? 'i-0simulatedc2' : scenario === 'cred' ? 'arn:aws:iam::4821:user/alice' : 'arn:aws:iam::4821:user/sim-attacker', currentAgent: 'Triage Agent', status: 'Investigating', created: new Date().toISOString().slice(0, 19).replace('T', ' '), description: 'Generated from the AgentSOC attack simulator to validate autonomous detection and response.', confidence: 92, sourceIp: '198.51.100.42', user: 'sim-attacker' }; setIncidents(items => [newIncident, ...items.filter(item => item.id !== 'INC-005')]); setEvents(items => [{ id: 'EVT-SIM-005', timestamp: new Date().toISOString().slice(11, 23), type: 'SimulatedThreatSignal', user: 'sim-attacker', sourceIp: '198.51.100.42', resource: newIncident.resource, risk: 'high' }, ...items]); notify('Scenario completed', '18 events emitted and INC-005 created in the incident queue.'); };
  return <AppCtx.Provider value={{ notify, reload: async () => { await reload(); } }}><QueryClientProvider client={queryClient}><TooltipProvider>{loading && <LoadingScreen isFadingOut={fadingOut} statusText={statusText} error={initError} onRetry={initialize} onContinueDemo={dismissLoading} />}<WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}><Shell onRefresh={onRefresh} refreshTick={refreshTick} mode={data.mode} pendingApprovals={data.approvals.filter(a => a.status === 'Pending').length}><RouterContent data={data} onToast={notify} onAction={onAction} onDecision={onDecision} onSimulate={onSimulate} onRunMonitor={onRunMonitor} onRunTriage={onRunTriage} onRunInvestigation={onRunInvestigation} onRunCompliance={onRunCompliance} onRunRemediation={onRunRemediation} onDecideApproval={onDecideApproval} onRunVerification={onRunVerification} onReset={onReset} onRefresh={onRefresh} /></Shell><Toast toast={toast} onClose={() => setToast(null)} /></WouterRouter><Toaster /></TooltipProvider></QueryClientProvider></AppCtx.Provider>;
}

export default App;