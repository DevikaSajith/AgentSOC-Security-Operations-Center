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
  type InvestigationInfo,
  type ComplianceInfo,
  type RemediationInfo,
  type VerificationInfo,
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
const TRIAGE_TIMEOUT_MS = 240_000;
const COMPLIANCE_TIMEOUT_MS = 480_000; // mapping-heavy prompt: up to two local LLM attempts
const REMEDIATION_TIMEOUT_MS = 480_000; // planning: up to two local LLM attempts
const APPROVAL_TIMEOUT_MS = 120_000; // approve = re-validate + execute + read back
const INVESTIGATION_TIMEOUT_MS = 420_000; // evidence-heavy prompt: up to two local LLM attempts // local LLM inference (backend LLM_TIMEOUT_SECONDS=180 + repair)
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
  compliance: ApiCompliance | null; remediation: ApiRemediation | null; verification: ApiVerification | null;
  triage: ApiTriage | null;
  investigation: ApiInvestigation | null;
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

type ApiInvestigation = {
  run_id: string; method: 'llm' | 'rule_based_fallback'; provider: string; model: string; timestamp: string;
  confidence: number; summary: string; recommended_next_step: string; root_cause_hypothesis: string;
  unknowns: string[]; limitations: string[]; alternative_hypotheses: string[];
  timeline: { evidence_id: string; timestamp: string | null; event_type: string; seconds_since_previous: number | null; shared_with_previous: string[]; significance: string | null }[];
  entities: { entity_id: string; type: string; value: string; evidence_ids: string[] }[];
  relationships: { source: string; relation: string; target: string; certainty: string }[];
  attack_sequence: { order: number; stage: string; description: string; evidence_ids: string[]; certainty: string; proposed_certainty: string; classification_note: string | null }[];
  findings: { finding_id: string; type: string; statement: string; evidence_ids: string[]; confidence: number; classification: string; proposed_confidence: number; proposed_certainty: string; classification_note: string | null }[];
  mitre_techniques: { technique_id: string; technique_name: string; tactic: string; confidence: number; evidence_ids: string[]; rationale: string; status: 'candidate' | 'confirmed'; validation_note: string }[];
  evidence: { evidence_id: string; type: string; source: string; observed: boolean; description: string }[];
};

type ApiCompliance = {
  run_id: string; method: 'llm' | 'rule_based_fallback'; provider: string; model: string; timestamp: string;
  based_on_investigation_run: string | null; confidence: number; overall_status: string; overall_note: string; summary: string;
  affected_assets: { asset_id: string; asset_type: string; identifier: string; classification: string; classification_basis: string; environment: string | null; owner: string | null }[];
  affected_data: { asset_id: string; identifier: string; classification: string; basis: string }[];
  controls: { control_id: string; control_name: string; status: string; proposed_status: string; evidence_ids: string[]; confidence: number; rationale: string; note: string | null }[];
  framework_assessments: { framework: string; framework_name: string; framework_control_id: string; framework_control_title: string; control_id: string; status: string; evidence_ids: string[]; rationale: string; source: string; note: string | null }[];
  control_gaps: { control_id: string; control_name: string; description: string; evidence_ids: string[] }[];
  potential_violations: { control_id: string; control_name: string; rule_id: string | null; status: string; proposed_status: string; statement: string; evidence_ids: string[]; note: string | null }[];
  reporting_status: string;
  reporting_considerations: { status: string; rule_id: string | null; requirement: string | null; note: string; evidence_ids: string[]; source: string }[];
  recommendations: { type: string; control_id: string | null; rationale: string; evidence_ids: string[] }[];
  unknowns: string[]; standing_unknowns: string[];
  matched_violation_rules: { rule_id: string; description: string }[];
  evidence: { evidence_id: string; type: string; source: string; observed: boolean; description: string }[];
};

type ApiApproval = {
  approval_id: string; incident_id: string; action: string; target: string; reason: string; risk: string;
  evidence_ids: string[]; status: string; expires_at: string; reviewed_by: string | null; decision: string | null;
};

type ApiRemediation = {
  run_id: string; status: string; method: 'llm' | 'rule_based_fallback' | 'no_candidates'; provider: string; model: string;
  timestamp: string; confidence: number; summary: string; based_on_compliance_run: string | null;
  plan: {
    plan_id: string; action: string; tool_name: string | null; target: string | null; arguments: Record<string, unknown>;
    reason: string; evidence_ids: string[]; expected_effect: string; risk: string; proposed_risk: string;
    requires_approval: boolean; rollback_available: boolean; rollback_description: string; excluded_actions: string[];
    policy_notes: { field: string; proposed: string; final: string; note: string }[];
  };
  approval: { approval_id: string; status: string; requested_at: string; expires_at: string; reviewed_at: string | null; reviewed_by: string | null; decision: string | null } | null;
  execution: { status: string; action: string | null; target: string | null; tool_name: string | null; approval_id: string | null; reason_code: string | null; message: string; before_state: Record<string, unknown> | null; after_state: Record<string, unknown> | null; executed_at: string | null };
  before_state: Record<string, unknown> | null; after_state: Record<string, unknown> | null;
  evidence: { evidence_id: string; type: string; source: string; observed: boolean; description: string }[];
  recommendations: string[]; unknowns: string[];
};

type ApiVerification = {
  run_id: string; status: string; method: string; action: string; target: string | null; expected_effect: string;
  expected_state: Record<string, unknown>; before_state: Record<string, unknown> | null; actual_state: Record<string, unknown> | null;
  comparison: { field: string; before: unknown; expected: unknown; actual: unknown; present: boolean; satisfied: boolean; changed_from_before: boolean }[];
  evidence: { evidence_id: string; type: string; source: string; description: string; data: Record<string, unknown> }[];
  confidence: number; reason: string; failure_reason: string | null; reported_execution_status: string | null;
  based_on_remediation_run: string | null; recommendations: string[]; timestamp: string;
};

type ApiVerificationReport = {
  run_id: string; incident_id: string; status: string; outcome: string; verification_status: string | null;
  validation_errors: string[]; verification: ApiVerification | null;
};

type ApiRemediationReport = {
  run_id: string; incident_id: string; status: string; outcome: string; method: string | null;
  provider: string | null; model: string | null; attempts: number; validation_errors: string[];
  remediation: ApiRemediation | null; approval: ApiApproval | null;
};

type ApiApprovalReport = {
  approval: ApiApproval; outcome: string; message: string; incident_status: string | null;
  execution: { status: string; reason_code: string | null; message: string };
};

type ApiComplianceReport = {
  run_id: string; incident_id: string; status: string; outcome: string; method: string | null;
  provider: string | null; model: string | null; attempts: number; validation_errors: string[];
  compliance: ApiCompliance | null;
};

type ApiInvestigationReport = {
  run_id: string; incident_id: string; status: string; outcome: string; method: string | null;
  provider: string | null; model: string | null; attempts: number; validation_errors: string[];
  investigation: ApiInvestigation | null;
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
    failed_runs?: number; fallback_runs?: number; last_incident_id?: string | null;
    pending_approvals?: number; executed_actions?: number;
    verified?: number; verification_failed?: number; partial?: number; unknown?: number; skipped?: number; method?: string } | null;
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
  new: 'New', triaging: 'New', triaged: 'Triaged', investigated: 'Investigated', compliance_assessed: 'Compliance assessed', investigating: 'Investigating', failed: 'Investigating',
  remediation_pending: 'Remediation pending', remediation_approved: 'Remediation approved', remediation_rejected: 'Remediation rejected',
  remediation_failed: 'Remediation failed', remediated: 'Remediated',
  verified: 'Verified', verification_failed: 'Verification failed', partial_remediation: 'Partial remediation', verification_unknown: 'Verification unknown',
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
        investigation: incident.investigation !== null, compliance: incident.compliance !== null,
        remediation: incident.remediation !== null, verification: incident.verification !== null,
      },
      triage: incident.triage ? toTriage(incident.triage) : null,
      investigation: incident.investigation ? toInvestigation(incident.investigation) : null,
      compliance: incident.compliance ? toCompliance(incident.compliance) : null,
      remediation: incident.remediation ? toRemediation(incident.remediation) : null,
      verification: incident.verification ? toVerification(incident.verification) : null,
    },
  };
}

const titleCase = (value: string) => { const text = value.replace(/_/g, ' '); return text.charAt(0).toUpperCase() + text.slice(1); };

function toApproval(a: ApiApproval): Approval {
  return {
    id: a.approval_id, action: titleCase(a.action), resource: a.target, reason: a.reason, requestedBy: 'Remediation Agent',
    risk: toSeverity(a.risk as ApiSeverity), incidentId: a.incident_id, status: titleCase(a.status) as Approval['status'],
    evidenceIds: a.evidence_ids, expiresAt: formatTime(a.expires_at), reviewedBy: a.reviewed_by, decision: a.decision,
  };
}

function toVerification(v: ApiVerification): VerificationInfo {
  return {
    runId: v.run_id, status: v.status, method: v.method, action: v.action, target: v.target, expectedEffect: v.expected_effect,
    expectedState: v.expected_state, beforeState: v.before_state, actualState: v.actual_state,
    comparison: v.comparison.map(c => ({ field: c.field, before: c.before, expected: c.expected, actual: c.actual, present: c.present, satisfied: c.satisfied, changed: c.changed_from_before })),
    evidence: v.evidence.map(e => ({ id: e.evidence_id, type: e.type, source: e.source, description: e.description, data: e.data })),
    confidence: v.confidence, reason: v.reason, failureReason: v.failure_reason, reportedExecution: v.reported_execution_status,
    basedOnRemediationRun: v.based_on_remediation_run, recommendations: v.recommendations, timestamp: formatTime(v.timestamp),
  };
}

function toRemediation(r: ApiRemediation): RemediationInfo {
  return {
    runId: r.run_id, status: r.status, method: r.method, provider: r.provider, model: r.model, timestamp: formatTime(r.timestamp),
    confidence: Math.round(r.confidence * 100), summary: r.summary, basedOnComplianceRun: r.based_on_compliance_run,
    plan: {
      id: r.plan.plan_id, action: r.plan.action, tool: r.plan.tool_name, target: r.plan.target, args: r.plan.arguments,
      reason: r.plan.reason, evidenceIds: r.plan.evidence_ids, expectedEffect: r.plan.expected_effect, risk: r.plan.risk,
      proposedRisk: r.plan.proposed_risk, requiresApproval: r.plan.requires_approval, rollbackAvailable: r.plan.rollback_available,
      rollbackDescription: r.plan.rollback_description, excluded: r.plan.excluded_actions, policyNotes: r.plan.policy_notes,
    },
    approval: r.approval ? {
      id: r.approval.approval_id, status: r.approval.status, requestedAt: formatTime(r.approval.requested_at),
      expiresAt: formatTime(r.approval.expires_at), reviewedAt: r.approval.reviewed_at ? formatTime(r.approval.reviewed_at) : null,
      reviewedBy: r.approval.reviewed_by, decision: r.approval.decision,
    } : null,
    execution: {
      status: r.execution.status, action: r.execution.action, target: r.execution.target, tool: r.execution.tool_name,
      approvalId: r.execution.approval_id, reasonCode: r.execution.reason_code, message: r.execution.message,
      before: r.execution.before_state, after: r.execution.after_state, executedAt: r.execution.executed_at ? formatTime(r.execution.executed_at) : null,
    },
    before: r.before_state, after: r.after_state,
    evidence: r.evidence.map(e => ({ id: e.evidence_id, type: e.type, source: e.source, observed: e.observed, description: e.description })),
    recommendations: r.recommendations, unknowns: r.unknowns,
  };
}

function toCompliance(c: ApiCompliance): ComplianceInfo {
  return {
    runId: c.run_id, method: c.method, provider: c.provider, model: c.model, timestamp: formatTime(c.timestamp),
    confidence: Math.round(c.confidence * 100), overallStatus: c.overall_status, overallNote: c.overall_note, summary: c.summary,
    basedOnInvestigationRun: c.based_on_investigation_run,
    assets: c.affected_assets.map(a => ({ id: a.asset_id, type: a.asset_type, identifier: a.identifier, classification: a.classification, basis: a.classification_basis, environment: a.environment, owner: a.owner })),
    data: c.affected_data.map(d => ({ id: d.asset_id, identifier: d.identifier, classification: d.classification, basis: d.basis })),
    controls: c.controls.map(x => ({ id: x.control_id, name: x.control_name, status: x.status, proposed: x.proposed_status, evidenceIds: x.evidence_ids, confidence: Math.round(x.confidence * 100), rationale: x.rationale, note: x.note })),
    frameworks: c.framework_assessments.map(f => ({ framework: f.framework, frameworkName: f.framework_name, controlId: f.framework_control_id, title: f.framework_control_title, control: f.control_id, status: f.status, evidenceIds: f.evidence_ids, rationale: f.rationale, source: f.source, note: f.note })),
    gaps: c.control_gaps.map(g => ({ control: g.control_id, name: g.control_name, description: g.description, evidenceIds: g.evidence_ids })),
    violations: c.potential_violations.map(v => ({ control: v.control_id, name: v.control_name, ruleId: v.rule_id, status: v.status, proposed: v.proposed_status, statement: v.statement, evidenceIds: v.evidence_ids, note: v.note })),
    reportingStatus: c.reporting_status,
    reporting: c.reporting_considerations.map(r => ({ status: r.status, ruleId: r.rule_id, requirement: r.requirement, note: r.note, evidenceIds: r.evidence_ids, source: r.source })),
    recommendations: c.recommendations.map(r => ({ type: r.type, control: r.control_id, rationale: r.rationale, evidenceIds: r.evidence_ids })),
    unknowns: c.unknowns, standingUnknowns: c.standing_unknowns,
    violationRules: c.matched_violation_rules.map(m => ({ id: m.rule_id, description: m.description })),
    evidence: c.evidence.map(e => ({ id: e.evidence_id, type: e.type, source: e.source, observed: e.observed, description: e.description })),
  };
}

function toInvestigation(v: ApiInvestigation): InvestigationInfo {
  const names = new Map(v.entities.map(e => [e.entity_id, `${e.type}: ${e.value}`]));
  return {
    runId: v.run_id, method: v.method, provider: v.provider, model: v.model, timestamp: formatTime(v.timestamp),
    confidence: Math.round(v.confidence * 100), summary: v.summary, nextStep: v.recommended_next_step,
    rootCause: v.root_cause_hypothesis, unknowns: v.unknowns, limitations: v.limitations, alternatives: v.alternative_hypotheses,
    timeline: v.timeline.map(t => ({ id: t.evidence_id, time: t.timestamp ? formatTime(t.timestamp, true) : 'unknown time', event: t.event_type, gap: t.seconds_since_previous, shares: t.shared_with_previous, note: t.significance })),
    entities: v.entities.map(e => ({ id: e.entity_id, type: e.type, value: e.value, evidenceIds: e.evidence_ids })),
    relationships: v.relationships.map(r => ({ from: names.get(r.source) ?? r.source, relation: r.relation, to: names.get(r.target) ?? r.target, certainty: r.certainty })),
    stages: v.attack_sequence.map(s => ({ order: s.order, stage: s.stage, description: s.description, evidenceIds: s.evidence_ids, certainty: s.certainty, proposed: s.proposed_certainty, note: s.classification_note })),
    findings: v.findings.map(f => ({ id: f.finding_id, type: f.type, statement: f.statement, evidenceIds: f.evidence_ids, confidence: Math.round(f.confidence * 100), classification: f.classification, proposedConfidence: Math.round(f.proposed_confidence * 100), proposedCertainty: f.proposed_certainty, note: f.classification_note })),
    mitre: v.mitre_techniques.map(m => ({ id: m.technique_id, name: m.technique_name, tactic: m.tactic, confidence: Math.round(m.confidence * 100), evidenceIds: m.evidence_ids, rationale: m.rationale, status: m.status, note: m.validation_note })),
    evidence: v.evidence.map(e => ({ id: e.evidence_id, type: e.type, source: e.source, observed: e.observed, description: e.description })),
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
      pendingApprovals: agent.stats.pending_approvals, executedActions: agent.stats.executed_actions,
      verified: agent.stats.verified, verificationFailed: agent.stats.verification_failed, partial: agent.stats.partial,
      unknown: agent.stats.unknown, skipped: agent.stats.skipped, method: agent.stats.method,
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
const fetchApprovals = async () => (await request<ApiApproval[]>('/approvals')).map(toApproval);
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

/** What one Investigator Agent run did. `investigation` is null when the run did not apply. */
export type InvestigationRunSummary = {
  runId: string; incidentId: string; status: string; outcome: string; method: string | null;
  provider: string | null; model: string | null; attempts: number; errors: string[]; investigation: InvestigationInfo | null;
};

/** Investigates one triaged incident (never triggers Triage). Throws on HTTP failure. */
export async function runInvestigation(incidentId: string): Promise<InvestigationRunSummary> {
  const report = await request<ApiInvestigationReport>('/agents/investigator/run', {
    method: 'POST', body: JSON.stringify({ incident_id: incidentId }),
  }, INVESTIGATION_TIMEOUT_MS);
  return {
    runId: report.run_id, incidentId: report.incident_id, status: report.status, outcome: report.outcome,
    method: report.method, provider: report.provider, model: report.model, attempts: report.attempts,
    errors: report.validation_errors, investigation: report.investigation ? toInvestigation(report.investigation) : null,
  };
}

/** What one Compliance Agent run did. `compliance` is null when the run did not apply. */
export type ComplianceRunSummary = {
  runId: string; incidentId: string; status: string; outcome: string; method: string | null;
  provider: string | null; model: string | null; attempts: number; errors: string[]; compliance: ComplianceInfo | null;
};

/** Assesses one investigated incident (never triggers Investigator). Throws on HTTP failure. */
export async function runCompliance(incidentId: string): Promise<ComplianceRunSummary> {
  const report = await request<ApiComplianceReport>('/agents/compliance/run', {
    method: 'POST', body: JSON.stringify({ incident_id: incidentId }),
  }, COMPLIANCE_TIMEOUT_MS);
  return {
    runId: report.run_id, incidentId: report.incident_id, status: report.status, outcome: report.outcome,
    method: report.method, provider: report.provider, model: report.model, attempts: report.attempts,
    errors: report.validation_errors, compliance: report.compliance ? toCompliance(report.compliance) : null,
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

/** What one Remediation Agent PLANNING run did. Running it never executes anything. */
export type RemediationRunSummary = {
  runId: string; incidentId: string; status: string; outcome: string; method: string | null;
  provider: string | null; model: string | null; attempts: number; errors: string[]; hasApproval: boolean;
};

/** Plans a remediation for one compliance-assessed incident (creates a pending approval; executes nothing). */
export async function runRemediation(incidentId: string): Promise<RemediationRunSummary> {
  const report = await request<ApiRemediationReport>('/agents/remediation/run', {
    method: 'POST', body: JSON.stringify({ incident_id: incidentId }),
  }, REMEDIATION_TIMEOUT_MS);
  return {
    runId: report.run_id, incidentId: report.incident_id, status: report.status, outcome: report.outcome,
    method: report.method, provider: report.provider, model: report.model, attempts: report.attempts,
    errors: report.validation_errors, hasApproval: report.approval !== null,
  };
}

/** What one Verification Agent run did. Verification is read-only: it never executes, approves or retries anything. */
export type VerificationRunSummary = {
  runId: string; incidentId: string; status: string; outcome: string; verificationStatus: string | null; errors: string[];
};

/** Verifies one remediated incident against the CURRENT cloud state. Safe to repeat. */
export async function runVerification(incidentId: string): Promise<VerificationRunSummary> {
  const report = await request<ApiVerificationReport>('/agents/verification/run', {
    method: 'POST', body: JSON.stringify({ incident_id: incidentId }),
  });
  return { runId: report.run_id, incidentId: report.incident_id, status: report.status, outcome: report.outcome,
    verificationStatus: report.verification_status, errors: report.validation_errors };
}

/** What a human decision on one approval did. `outcome` is machine-readable (executed, rejected, actions_disabled, ...). */
export type ApprovalDecisionSummary = { ok: boolean; outcome: string; message: string; executionStatus: string | null; incidentStatus: string | null };

/** The analyst approves / rejects / (re)executes ONE approval. The frontend only requests it: the backend
 *  re-validates, checks policy and the kill switch, and executes through the ToolExecutor. */
export async function decideApproval(approvalId: string, decision: 'approve' | 'reject' | 'execute'): Promise<ApprovalDecisionSummary> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), APPROVAL_TIMEOUT_MS);
  try {
    const response = await fetch(`${API_URL}/approvals/${encodeURIComponent(approvalId)}/${decision}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: decision === 'execute' ? undefined : '{}', signal: controller.signal,
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      const detail = body?.detail; const text = typeof detail === 'string' ? detail : (detail?.detail ?? `request failed (${response.status})`);
      return { ok: false, outcome: detail?.code ?? 'request_failed', message: text, executionStatus: null, incidentStatus: null };
    }
    const report = body as ApiApprovalReport;
    return { ok: true, outcome: report.outcome, message: report.message, executionStatus: report.execution.status, incidentStatus: report.incident_status };
  } catch {
    return { ok: false, outcome: 'backend_unreachable', message: 'The backend did not answer. Nothing was changed.', executionStatus: null, incidentStatus: null };
  } finally {
    window.clearTimeout(timer);
  }
}

/** Resets the simulated cloud on the backend (event history is kept). */
export async function resetEnvironment(): Promise<{ status: string }> {
  await request('/simulation/reset', { method: 'POST' });
  return { status: 'reset' };
}

// DEMO MODE ONLY: with no backend the Approval Center records decisions locally. In live mode
// approvals are decided with decideApproval() and executed by the backend.
export async function approveAction(approval: Approval): Promise<Approval> {
  return { ...approval, status: 'Approved' };
}

export async function rejectAction(approval: Approval): Promise<Approval> {
  return { ...approval, status: 'Rejected' };
}
