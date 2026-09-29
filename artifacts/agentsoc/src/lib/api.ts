import {
  seedAgents,
  seedApprovals,
  seedAudit,
  seedEvents,
  seedIncidents,
  seedResources,
  type Agent,
  type Approval,
  type AuditEntry,
  type CloudResource,
  type Incident,
  type IncidentStatus,
  type SecurityEvent,
  type Severity,
  type TriageInfo,
} from '@/data';

/*
 * Data access for the dashboard.
 *
 * `live` mode: data comes from the FastAPI backend (default base URL `/api`, which the Vite
 * dev server proxies to http://localhost:8000). `demo` mode: the backend is unreachable (or
 * VITE_DEMO_MODE=true), so the bundled seed data in `data.ts` is used instead.
 */

const API_URL = (import.meta.env.VITE_API_URL ?? import.meta.env.NEXT_PUBLIC_API_URL ?? '/api').replace(/\/$/, '');
const FORCE_DEMO = import.meta.env.VITE_DEMO_MODE === 'true';
const REQUEST_TIMEOUT_MS = 5000;
const TRIAGE_TIMEOUT_MS = 240_000; // local LLM inference (backend LLM_TIMEOUT_SECONDS=180 + repair)
const BACKEND_SERVICE = 'agentsoc-backend';

export type DataMode = 'live' | 'demo';

async function request<T>(path: string, init?: RequestInit, timeoutMs = REQUEST_TIMEOUT_MS): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`AgentSOC API request failed: ${response.status}`);
    }
    if (!(response.headers.get('content-type') ?? '').includes('application/json')) {
      throw new Error('AgentSOC API returned a non-JSON response');
    }
    return (await response.json()) as T;
  } finally {
    window.clearTimeout(timer);
  }
}

/* ------------------------------------------------------------------ backend shapes */

type ApiSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

type ApiEvent = {
  event_id: string; timestamp: string; source: string; event_type: string; user: string;
  principal_id: string; source_ip: string; resource_type: string; resource_id: string;
  severity: ApiSeverity;
};

type ApiIncident = {
  incident_id: string; timestamp: string; title: string; description: string; source: string;
  event_type: string; account_id: string; region: string;
  resource_id: string | null; principal_id: string | null; source_ip: string | null;
  severity: ApiSeverity; priority: string | null; category: string; confidence: number;
  current_agent: string | null; final_status: string; related_event_ids: string[];
  affected_resources: { resource_type: string; resource_id: string }[];
  evidence: { evidence_id: string; kind: string; description: string; event_id: string | null; data: Record<string, unknown> }[];
  agent_decisions: { actor: string; decision: string; reasoning: string; confidence: number; timestamp: string }[];
  investigation: unknown; compliance_findings: unknown[]; remediation_plan: unknown; verification_result: unknown;
  triage: ApiTriage | null;
};

type ApiTriage = {
  run_id: string; method: 'llm' | 'rule_based_fallback'; provider: string; model: string; timestamp: string;
  input_event_ids: string[]; severity: string; priority: string; category: string; confidence: number;
  previous: { severity: string; priority: string | null; category: string; confidence: number };
  observed_evidence: { ref: string; kind: string; fact: string }[];
  interpretation: {
    classification: string; summary: string; severity_rationale: string; priority_rationale: string;
    risk_indicators: { indicator: string; evidence_refs: string[] }[]; investigation_reason: string;
  };
  investigation_required: boolean; recommended_next_step: string;
};

type ApiTriageReport = {
  run_id: string; incident_id: string; status: string; outcome: string; method: string | null;
  provider: string | null; model: string | null; attempts: number; validation_errors: string[];
  triage: ApiTriage | null;
};

type ApiAgentResult = {
  status: string; outcome: string; confidence: number; reasoning_summary: string;
  incident_id: string | null; findings: string[];
};

type ApiAgent = {
  agent_id: string; name: string; purpose: string; input: string; output: string;
  tools: string[]; implemented: boolean; status: string; tasks_processed: number;
  last_activity: string | null;
  stats: { runs: number; last_run_at: string | null; events_processed?: number; incidents_created?: number;
    incidents_updated?: number; events_rejected?: number; duplicates?: number; successful_runs?: number;
    failed_runs?: number; fallback_runs?: number; last_incident_id?: string | null } | null;
  last_result: ApiAgentResult | null;
  llm?: { configured: boolean; provider: string; model: string | null; error: string | null } | null;
};

type ApiMonitorReport = {
  run_id: string; processed_events: number; accepted_event_ids: string[];
  rejected_events: { index: number | null; event_id: string | null; reason: string }[];
  duplicates: { event_id: string; duplicate_of: string; kind: string }[];
  already_processed: string[];
  correlated_groups: { group_id: string; event_ids: string[]; principal_id: string; decision: string; incident_id: string | null; indicators: string[]; confidence: number }[];
  incidents_created: string[]; incidents_updated: string[];
  agent_result: ApiAgentResult;
};

type ApiCloudState = {
  resources: { category: string; name: string; detail: string; status: CloudResource['status'] }[];
  summary: { total: number; healthy: number; at_risk: number; exposed: number; isolated: number };
};

type ApiEventStats = {
  total_events: number; events_today: number; users_with_events: number;
  by_severity: Record<string, number>;
};

type ApiAuditEntry = {
  audit_id: string; timestamp: string; incident_id: string | null; actor: string; action: string;
  decision: string; result: string; reasoning: string; confidence: number | null;
  details: Record<string, unknown>;
};

type ApiRunResult = { scenario: string; events_generated: number; event_ids: string[]; incident_id: string | null };

/* ------------------------------------------------------------------------- mappers */

const toSeverity = (value: ApiSeverity): Severity => (value === 'info' ? 'low' : value);
const formatTime = (iso: string, withMillis = false) => iso.replace('T', ' ').slice(0, withMillis ? 23 : 19);

const INCIDENT_STATUS: Record<string, IncidentStatus> = {
  new: 'New', triaging: 'New', triaged: 'Triaged', investigating: 'Investigating', failed: 'Investigating',
  awaiting_approval: 'Awaiting approval', remediating: 'Contained', contained: 'Contained',
  resolved: 'Resolved', false_positive: 'Resolved',
};

function toEvent(event: ApiEvent): SecurityEvent {
  return {
    id: event.event_id, timestamp: formatTime(event.timestamp, true), type: event.event_type,
    user: event.principal_id ?? event.user, sourceIp: event.source_ip, resource: event.resource_id,
    risk: toSeverity(event.severity),
  };
}

function toIncident(incident: ApiIncident): Incident {
  return {
    id: incident.incident_id, title: incident.title, severity: toSeverity(incident.severity),
    source: incident.source,
    resource: incident.resource_id ?? incident.affected_resources[0]?.resource_id ?? '—',
    currentAgent: incident.current_agent ?? '—',
    status: INCIDENT_STATUS[incident.final_status] ?? 'Investigating',
    created: formatTime(incident.timestamp), description: incident.description,
    confidence: Math.round(incident.confidence * 100), sourceIp: incident.source_ip ?? '—',
    user: incident.principal_id ?? '—',
    detail: {
      category: incident.category, priority: incident.priority, eventType: incident.event_type,
      accountId: incident.account_id, region: incident.region, relatedEventIds: incident.related_event_ids,
      affected: incident.affected_resources.map(r => `${r.resource_type}/${r.resource_id}`),
      evidence: incident.evidence.map(e => {
        const text = (key: string) => (typeof e.data[key] === 'string' ? (e.data[key] as string) : null);
        return {
          id: e.evidence_id, kind: e.kind, description: e.description, eventId: e.event_id,
          timestamp: text('timestamp'), eventType: text('event_type'), source: text('source'),
          sourceIp: text('source_ip'), severity: text('severity'),
          indicators: Array.isArray(e.data.indicators) ? (e.data.indicators as string[]) : [],
        };
      }),
      decisions: incident.agent_decisions.map(d => ({
        actor: d.actor, decision: d.decision, reasoning: d.reasoning,
        confidence: Math.round(d.confidence * 100), timestamp: formatTime(d.timestamp),
      })),
      stages: {
        investigation: incident.investigation !== null, compliance: incident.compliance_findings.length > 0,
        remediation: incident.remediation_plan !== null, verification: incident.verification_result !== null,
      },
      triage: incident.triage ? toTriage(incident.triage) : null,
    },
  };
}

function toTriage(t: ApiTriage): TriageInfo {
  return {
    runId: t.run_id, method: t.method, provider: t.provider, model: t.model, timestamp: formatTime(t.timestamp),
    severity: t.severity, priority: t.priority, category: t.category, confidence: Math.round(t.confidence * 100),
    previous: { severity: t.previous.severity, priority: t.previous.priority, category: t.previous.category },
    classification: t.interpretation.classification, summary: t.interpretation.summary,
    severityRationale: t.interpretation.severity_rationale, priorityRationale: t.interpretation.priority_rationale,
    riskIndicators: t.interpretation.risk_indicators.map(r => ({ indicator: r.indicator, refs: r.evidence_refs })),
    observed: t.observed_evidence.map(o => ({ ref: o.ref, kind: o.kind, fact: o.fact })),
    investigationRequired: t.investigation_required, investigationReason: t.interpretation.investigation_reason,
    nextStep: t.recommended_next_step, inputEventIds: t.input_event_ids,
  };
}

function toAgent(agent: ApiAgent): Agent {
  const last = agent.last_result;
  return {
    id: agent.agent_id, name: agent.name,
    status: agent.implemented ? (agent.status === 'running' ? 'Active' : 'Ready') : 'Not implemented',
    purpose: agent.purpose, tools: agent.tools, tasks: agent.tasks_processed,
    lastActivity: agent.implemented
      ? (agent.last_activity ? `last run ${formatTime(agent.last_activity)}` : 'never run')
      : 'not implemented yet',
    input: agent.input, output: agent.output, implemented: agent.implemented,
    llm: agent.llm ?? null,
    stats: agent.stats ? {
      runs: agent.stats.runs, eventsProcessed: agent.stats.events_processed,
      incidentsCreated: agent.stats.incidents_created, incidentsUpdated: agent.stats.incidents_updated,
      eventsRejected: agent.stats.events_rejected, duplicates: agent.stats.duplicates,
      successfulRuns: agent.stats.successful_runs, failedRuns: agent.stats.failed_runs,
      fallbackRuns: agent.stats.fallback_runs, lastIncidentId: agent.stats.last_incident_id,
      lastRunAt: agent.stats.last_run_at ? formatTime(agent.stats.last_run_at) : null,
      lastResult: last ? {
        status: last.status, outcome: last.outcome, confidence: Math.round(last.confidence * 100),
        summary: last.reasoning_summary, incidentId: last.incident_id, findings: last.findings,
      } : null,
    } : undefined,
  };
}

function toAuditEntry(entry: ApiAuditEntry): AuditEntry {
  return {
    id: entry.audit_id, timestamp: formatTime(entry.timestamp), agent: entry.actor, action: entry.action,
    decision: entry.decision, result: entry.result, incidentId: entry.incident_id ?? '—',
    input: Object.keys(entry.details).length ? JSON.stringify(entry.details) : '—',
    reason: entry.reasoning || '—',
    confidence: entry.confidence === null ? null : Math.round(entry.confidence * 100),
  };
}

/* ------------------------------------------------------------------ public types */

export type CloudState = {
  resources: CloudResource[];
  status: 'online' | 'degraded';
  summary?: ApiCloudState['summary'];
};

export type DashboardStats = {
  totalEvents: number;
  eventsToday: number;
  activeIncidents: number;
  criticalIncidents: number;
  pendingApprovals: number;
};

export type ScenarioResult = {
  scenario: string;
  eventsGenerated: number;
  eventIds: string[];
  incidentId: string | null;
};

/** What one Monitor Agent run did (from POST /api/agents/monitor/run). */
export type MonitorRunSummary = {
  runId: string;
  status: string;
  outcome: string;
  confidence: number;
  summary: string;
  processed: number;
  rejected: number;
  duplicates: number;
  alreadyProcessed: number;
  groups: { id: string; events: number; principal: string; decision: string; incidentId: string | null; indicators: string[] }[];
  incidentsCreated: string[];
  incidentsUpdated: string[];
};

export type DashboardData = {
  mode: DataMode;
  incidents: Incident[];
  events: SecurityEvent[];
  agents: Agent[];
  approvals: Approval[];
  audit: AuditEntry[];
  cloud: CloudState;
  stats: DashboardStats;
};

/** UI scenario ids -> backend scenario names. */
export const SCENARIOS: Record<string, string> = {
  iam: 'iam_privilege_escalation',
  s3: 'public_s3_exposure',
  ec2: 'ec2_compromise',
  cred: 'credential_misuse',
};

const demoStats: DashboardStats = {
  totalEvents: 1284, eventsToday: 1284, activeIncidents: 4, criticalIncidents: 1, pendingApprovals: 2,
};

export const demoData: DashboardData = {
  mode: 'demo',
  incidents: seedIncidents,
  events: seedEvents,
  agents: seedAgents,
  approvals: seedApprovals,
  audit: seedAudit,
  cloud: { resources: seedResources, status: 'online' },
  stats: demoStats,
};

async function withDemoFallback<T>(remote: () => Promise<T>, demo: T): Promise<T> {
  if (FORCE_DEMO) return demo;
  try {
    return await remote();
  } catch {
    return demo;
  }
}

/* ------------------------------------------------------------------ live requests */

/** True when the AgentSOC FastAPI backend (not some other /api service) is reachable. */
export async function isBackendAvailable(): Promise<boolean> {
  if (FORCE_DEMO) return false;
  try {
    const health = await request<{ status?: string; service?: string }>('/healthz');
    return health.status === 'ok' && health.service === BACKEND_SERVICE;
  } catch {
    return false;
  }
}

const fetchEvents = async () => (await request<ApiEvent[]>('/events?limit=500')).map(toEvent);
const fetchIncidents = async () => (await request<ApiIncident[]>('/incidents')).map(toIncident);
const fetchAgents = async () => (await request<ApiAgent[]>('/agents')).map(toAgent);
const fetchApprovals = () => request<Approval[]>('/approvals');
const fetchAudit = async () => (await request<ApiAuditEntry[]>('/audit')).map(toAuditEntry);

async function fetchCloudState(): Promise<CloudState> {
  const state = await request<ApiCloudState>('/cloud/state');
  return { resources: state.resources, status: 'online', summary: state.summary };
}

async function fetchStats(incidents?: Incident[], approvals?: Approval[]): Promise<DashboardStats> {
  const [events, liveIncidents, liveApprovals] = await Promise.all([
    request<ApiEventStats>('/events/stats'),
    incidents ?? fetchIncidents(),
    approvals ?? fetchApprovals(),
  ]);
  return {
    totalEvents: events.total_events,
    eventsToday: events.events_today,
    activeIncidents: liveIncidents.filter(item => item.status !== 'Resolved').length,
    criticalIncidents: liveIncidents.filter(item => item.severity === 'critical').length,
    pendingApprovals: liveApprovals.filter(item => item.status === 'Pending').length,
  };
}

/** Everything the dashboard needs, from the backend if reachable, otherwise demo data. */
export async function loadDashboard(): Promise<DashboardData> {
  if (!(await isBackendAvailable())) return demoData;
  try {
    const [incidents, events, agents, approvals, audit, cloud] = await Promise.all([
      fetchIncidents(), fetchEvents(), fetchAgents(), fetchApprovals(), fetchAudit(), fetchCloudState(),
    ]);
    const stats = await fetchStats(incidents, approvals);
    return { mode: 'live', incidents, events, agents, approvals, audit, cloud, stats };
  } catch {
    return demoData;
  }
}

export async function getCloudState(): Promise<CloudState> {
  return withDemoFallback(fetchCloudState, demoData.cloud);
}

export async function getEvents(): Promise<SecurityEvent[]> {
  return withDemoFallback(fetchEvents, seedEvents);
}

export async function getIncidents(): Promise<Incident[]> {
  return withDemoFallback(fetchIncidents, seedIncidents);
}

export async function getStats(): Promise<DashboardStats> {
  return withDemoFallback(() => fetchStats(), demoStats);
}

export async function getAgents(): Promise<Agent[]> {
  return withDemoFallback(fetchAgents, seedAgents);
}

/** Runs a scenario on the backend. Throws on failure: a live run is never faked. */
export async function runScenario(scenario: string): Promise<ScenarioResult> {
  const result = await request<ApiRunResult>('/simulation/run', {
    method: 'POST',
    body: JSON.stringify({ scenario: SCENARIOS[scenario] ?? scenario }),
  });
  return {
    scenario: result.scenario, eventsGenerated: result.events_generated,
    eventIds: result.event_ids, incidentId: result.incident_id,
  };
}

/** What one Triage Agent run did. `triage` is null when the run failed (incident unchanged). */
export type TriageRunSummary = {
  runId: string; incidentId: string; status: string; outcome: string; method: string | null;
  provider: string | null; model: string | null; attempts: number; errors: string[]; triage: TriageInfo | null;
};

/** Triages one incident. LLM runs can take tens of seconds on a local model. Throws on HTTP failure. */
export async function runTriage(incidentId: string): Promise<TriageRunSummary> {
  const report = await request<ApiTriageReport>('/agents/triage/run', {
    method: 'POST', body: JSON.stringify({ incident_id: incidentId }),
  }, TRIAGE_TIMEOUT_MS);
  return {
    runId: report.run_id, incidentId: report.incident_id, status: report.status, outcome: report.outcome,
    method: report.method, provider: report.provider, model: report.model, attempts: report.attempts,
    errors: report.validation_errors, triage: report.triage ? toTriage(report.triage) : null,
  };
}

/** Runs the Monitor Agent on the given stored events (or on all unprocessed ones). Throws on failure. */
export async function runMonitor(eventIds?: string[]): Promise<MonitorRunSummary> {
  const report = await request<ApiMonitorReport>('/agents/monitor/run', {
    method: 'POST',
    body: JSON.stringify(eventIds ? { event_ids: eventIds } : {}),
  });
  const result = report.agent_result;
  return {
    runId: report.run_id, status: result.status, outcome: result.outcome,
    confidence: Math.round(result.confidence * 100), summary: result.reasoning_summary,
    processed: report.processed_events, rejected: report.rejected_events.length,
    duplicates: report.duplicates.length, alreadyProcessed: report.already_processed.length,
    groups: report.correlated_groups.map(g => ({
      id: g.group_id, events: g.event_ids.length, principal: g.principal_id, decision: g.decision,
      incidentId: g.incident_id, indicators: g.indicators,
    })),
    incidentsCreated: report.incidents_created, incidentsUpdated: report.incidents_updated,
  };
}

/** Resets the simulated cloud on the backend (event history is kept). */
export async function resetEnvironment(): Promise<{ status: string }> {
  await request('/simulation/reset', { method: 'POST' });
  return { status: 'reset' };
}

// The approval workflow has no backend yet (it arrives with the Remediation Agent), so
// decisions are recorded locally only.
export async function approveAction(approval: Approval): Promise<Approval> {
  return { ...approval, status: 'Approved' };
}

export async function rejectAction(approval: Approval): Promise<Approval> {
  return { ...approval, status: 'Rejected' };
}
