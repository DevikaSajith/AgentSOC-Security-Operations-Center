import {
  seedAgents,
  seedEvents,
  seedIncidents,
  seedResources,
  type Agent,
  type Approval,
  type Incident,
  type SecurityEvent,
} from '@/data';

const API_URL = (import.meta.env.VITE_API_URL ?? import.meta.env.NEXT_PUBLIC_API_URL ?? '/api').replace(/\/$/, '');

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });

  if (!response.ok) {
    throw new Error(`AgentSOC API request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

async function withDemoFallback<T>(remote: () => Promise<T>, demo: T): Promise<T> {
  if (!import.meta.env.VITE_API_URL && !import.meta.env.NEXT_PUBLIC_API_URL) {
    return demo;
  }

  try {
    return await remote();
  } catch {
    return demo;
  }
}

export type CloudState = {
  resources: typeof seedResources;
  status: 'online' | 'degraded';
};

export type DashboardStats = {
  totalEvents: number;
  activeIncidents: number;
  criticalIncidents: number;
  pendingApprovals: number;
};

export type ScenarioResult = {
  scenario: string;
  eventsGenerated: number;
  incidentId: string;
};

export async function getCloudState(): Promise<CloudState> {
  return withDemoFallback(() => request<CloudState>('/cloud/state'), {
    resources: seedResources,
    status: 'online',
  });
}

export async function getEvents(): Promise<SecurityEvent[]> {
  return withDemoFallback(() => request<SecurityEvent[]>('/events'), seedEvents);
}

export async function getIncidents(): Promise<Incident[]> {
  return withDemoFallback(() => request<Incident[]>('/incidents'), seedIncidents);
}

export async function getStats(): Promise<DashboardStats> {
  return withDemoFallback(() => request<DashboardStats>('/events/stats'), {
    totalEvents: 1284,
    activeIncidents: 4,
    criticalIncidents: 1,
    pendingApprovals: 2,
  });
}

export async function getAgents(): Promise<Agent[]> {
  return withDemoFallback(() => request<Agent[]>('/agents'), seedAgents);
}

export async function runScenario(scenario: string): Promise<ScenarioResult> {
  return withDemoFallback(
    () =>
      request<ScenarioResult>('/simulation/run', {
        method: 'POST',
        body: JSON.stringify({ scenario }),
      }),
    { scenario, eventsGenerated: 18, incidentId: 'INC-005' },
  );
}

export async function resetEnvironment(): Promise<{ status: string }> {
  return withDemoFallback(
    () => request<{ status: string }>('/reset', { method: 'POST' }),
    { status: 'reset' },
  );
}

export async function approveAction(approval: Approval): Promise<Approval> {
  return withDemoFallback(
    () =>
      request<Approval>('/cloud/action', {
        method: 'POST',
        body: JSON.stringify({ approvalId: approval.id, decision: 'Approved' }),
      }),
    { ...approval, status: 'Approved' },
  );
}

export async function rejectAction(approval: Approval): Promise<Approval> {
  return withDemoFallback(
    () =>
      request<Approval>('/cloud/action', {
        method: 'POST',
        body: JSON.stringify({ approvalId: approval.id, decision: 'Rejected' }),
      }),
    { ...approval, status: 'Rejected' },
  );
}