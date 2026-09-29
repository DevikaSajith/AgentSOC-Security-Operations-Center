# AgentSOC — Architecture Analysis

## CURRENT ARCHITECTURE

### Backend
- **Framework**: Express 5 (TypeScript/Node.js) — `artifacts/api-server/`
- **DB Client**: Drizzle ORM with PostgreSQL (`lib/db/`) — schema is **empty** (only comments/examples)
- **API Routes**: Only `/api/healthz` exists — no domain routes at all
- **Middleware**: CORS, pino logging, JSON body parsing
- **Build**: esbuild via `build.mjs`

### Frontend
- **Framework**: React 19 + Vite + TailwindCSS + Wouter (routing)
- **Data**: 100% static seed data in `artifacts/agentsoc/src/data.ts`
- **Pages**: SOC Overview, Incidents, Events, Agents, Approvals, Cloud, Simulator, Analytics, Audit
- **API Integration**: `VITE_API_URL` env var exists but is unused — frontend runs in standalone demo mode
- **UI Library**: Radix UI components, Lucide icons, Recharts
- **State**: Local React state only (no server state fetching)

### Simulator
- **Exists**: Only as UI in `SimulatorPage` — clicking a scenario sets a timer, shows "18 events generated"
- **No actual simulation**: All outputs are hardcoded static values
- **No backend call**: `onSimulate(id)` adds a new incident to local state

### Database
- **Technology**: PostgreSQL (via `DATABASE_URL` env var), Drizzle ORM
- **Schema**: EMPTY — `lib/db/src/schema/index.ts` has only commented examples
- **No tables exist** yet

### Existing LLM Integration
- **None** — no Groq, OpenAI, or any LLM client exists in the codebase

### Existing APIs
| Endpoint | Method | Status |
|---|---|---|
| `/api/healthz` | GET | Working |

### Existing Event Schema (Frontend)
- `SecurityEvent`: `{ id, timestamp, type, user, sourceIp, resource, risk }`
- `Incident`: `{ id, title, severity, source, resource, currentAgent, status, created, description, confidence, sourceIp, user }`
- `Approval`: `{ id, action, resource, reason, requestedBy, risk, incidentId, status }`
- `AuditEntry`: `{ timestamp, agent, action, decision, result, incidentId, input, reason, confidence }`

### Existing Attack Scenarios (UI only, no real logic)
1. IAM Privilege Escalation
2. Public S3 Exposure
3. EC2 Command & Control
4. Credential Misuse (in seed data)

### Technology Stack
- Node.js 24 + Python 3.13 (both available per `.replit`)
- pnpm workspace monorepo
- TypeScript frontend + Express backend
- React 19, Vite 7, TailwindCSS 4, Wouter, Recharts, Radix UI

---

## PROPOSED ARCHITECTURE

### Decision: Python FastAPI Backend for Agent Intelligence

The `.replit` config explicitly includes `python-base-3.13`. LangGraph, Pydantic v2, and Groq SDK are Python-native. The agent pipeline will be implemented as a Python FastAPI service running alongside the existing Node.js Express service.

```
Frontend (React/Vite :3000)
    |
    +-> VITE_API_URL -> Python FastAPI Backend (:8000)
    |       +-- POST /api/simulation/run
    |       +-- GET  /api/incidents
    |       +-- GET  /api/incidents/{id}
    |       +-- POST /api/incidents/{id}/approve
    |       +-- POST /api/incidents/{id}/reject
    |       +-- GET  /api/events
    |       +-- GET  /api/agents/status
    |       +-- GET  /api/audit
    |       +-- GET  /api/approvals
    |       +-- GET  /api/metrics
    |
    +-> Express Backend (:5000) [existing, keep as-is]
            +-- GET /api/healthz
```

### Python Backend Structure
```
backend/
+-- main.py                 FastAPI app entry point
+-- requirements.txt
+-- .env.example
+-- schemas/
|   +-- models.py           CloudEvent, Incident, AgentState, AgentDecision, etc.
+-- simulator/
|   +-- cloud_simulator.py  Generates realistic cloud event sequences
+-- agents/
|   +-- monitor/agent.py    Event collection + normalization
|   +-- triage/agent.py     LLM-based incident classification
|   +-- triage/prompt.py    Structured prompts
|   +-- triage/rules.py     Deterministic fallback rules
|   +-- investigator/agent.py  Attack chain reconstruction + MITRE mapping
|   +-- compliance/agent.py    Policy rule evaluation
|   +-- remediation/agent.py   Deterministic action execution
+-- graph/
|   +-- state.py            LangGraph AgentState TypedDict
|   +-- nodes.py            LangGraph node functions (one per agent)
|   +-- workflow.py         LangGraph StateGraph with conditional edges
+-- tools/
|   +-- events/query_tools.py   get_user_activity, get_related_events, etc.
|   +-- mitre/lookup.py         MITRE ATT&CK knowledge base
|   +-- compliance/policy.py    Compliance rule engine
|   +-- remediation/sim_tools.py Deterministic simulator actions
+-- database/
|   +-- db.py               SQLite via SQLAlchemy (lightweight, no PostgreSQL needed)
+-- api/
    +-- routes.py           FastAPI route handlers
```

### Config Files
```
config/
+-- compliance_rules.yaml   Policy rules (IAM-001, EC2-001, S3-001)
+-- mitre_mapping.yaml      MITRE ATT&CK technique knowledge base
+-- agent_config.yaml       Agent thresholds and behavior configuration
```

---

## REUSABLE COMPONENTS

| Component | Status | Notes |
|---|---|---|
| Frontend UI shell | Full reuse | All pages preserved as-is |
| `data.ts` seed data | Keep as fallback | Used when VITE_API_URL not set |
| Express health route | Keep | No changes needed |
| Incident/Event type shapes | Match in Python | Python Pydantic models mirror frontend types |
| Approval UI + flow | Full reuse | Wire to `/api/incidents/{id}/approve` |
| Audit log UI | Full reuse | Wire to `/api/audit` |

---

## FILES TO MODIFY (Existing)

| File | Change |
|---|---|
| `artifacts/agentsoc/src/App.tsx` | Add API fetch on simulation run; keep seed data as fallback |

## FILES TO CREATE (New)

### Python Backend
- `backend/main.py`
- `backend/requirements.txt`
- `backend/.env.example`
- `backend/schemas/__init__.py`
- `backend/schemas/models.py`
- `backend/simulator/__init__.py`
- `backend/simulator/cloud_simulator.py`
- `backend/agents/monitor/__init__.py`
- `backend/agents/monitor/agent.py`
- `backend/agents/triage/__init__.py`
- `backend/agents/triage/agent.py`
- `backend/agents/triage/prompt.py`
- `backend/agents/triage/rules.py`
- `backend/agents/investigator/__init__.py`
- `backend/agents/investigator/agent.py`
- `backend/agents/compliance/__init__.py`
- `backend/agents/compliance/agent.py`
- `backend/agents/remediation/__init__.py`
- `backend/agents/remediation/agent.py`
- `backend/graph/state.py`
- `backend/graph/nodes.py`
- `backend/graph/workflow.py`
- `backend/tools/events/__init__.py`
- `backend/tools/events/query_tools.py`
- `backend/tools/mitre/__init__.py`
- `backend/tools/mitre/lookup.py`
- `backend/tools/compliance/__init__.py`
- `backend/tools/compliance/policy.py`
- `backend/tools/remediation/__init__.py`
- `backend/tools/remediation/sim_tools.py`
- `backend/database/__init__.py`
- `backend/database/db.py`
- `backend/api/__init__.py`
- `backend/api/routes.py`

### Config
- `config/compliance_rules.yaml`
- `config/mitre_mapping.yaml`
- `config/agent_config.yaml`

### Scenarios
- `scenarios/credential_misuse/events.json`

### Tests
- `tests/__init__.py`
- `tests/test_schemas.py`
- `tests/test_monitor.py`
- `tests/test_triage.py`
- `tests/test_investigator.py`
- `tests/test_compliance.py`
- `tests/test_remediation.py`
- `tests/test_workflow.py`

### Docs
- `docs/end_to_end_demo.md`
