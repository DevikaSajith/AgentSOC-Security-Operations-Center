# 🛡️ AgentSOC — Autonomous Cloud Security Operations Center

> **AgentSOC** is a simulated autonomous cloud security operations center designed for investigating AWS threats, orchestrating multi-agent investigations, enforcing human-in-the-loop remediation approvals, and maintaining an immutable decision audit trail.

---

## 🌟 Key Features

- **5-Agent Response Pipeline** *(agents are designed but not implemented yet — see "Backend" below)*:
  - 🔍 **Monitor Agent**: Ingests raw telemetry and normalizes multi-source events into high-confidence threat signals.
  - ⚖️ **Triage Agent**: Prioritizes alerts, correlates identity chains, and assesses environmental risk.
  - 🔎 **Investigator Agent**: Queries identity graphs, maps blast radius, and maps behaviors to MITRE ATT&CK techniques (e.g., T1098).
  - 🛡️ **Compliance Agent**: Checks findings and proposed actions against policy, verifies reversibility.
  - ⚡ **Remediation Agent**: Drafts targeted containment actions gated behind human authorization.
- **Interactive SOC Command Center**:
  - **Overview (`/`)**: Threat activity graphs, risk distribution metrics, and environment posture score (e.g. 87/100).
  - **Incidents (`/incidents`)**: Filterable incident queue with attack timelines, agent decision traces, forensic evidence (CloudTrail events, policy diffs, session fingerprints), and blast-radius summaries.
  - **Security Events (`/events`)**: Correlated telemetry stream with multi-field filtering and one-click CSV export.
  - **Agent Network (`/agents`)**: Agent directory with input/output contracts, scoped tools, execution statistics, and decision histories.
  - **Approval Center (`/approvals`)**: Strict human gate for reviewing and approving or rejecting proposed containment actions (e.g. revoking admin policies, isolating EC2 workloads).
  - **Cloud Environment (`/cloud`)**: Visual inventory of monitored AWS resources (IAM, S3, EC2) and their current security posture.
  - **Attack Simulator (`/simulator`)**: One-click sandboxed threat emulation scenarios:
    - *IAM Privilege Escalation*: `AttachUserPolicy` on a non-admin CI principal.
    - *Public S3 Exposure*: Opening production export buckets to anonymous access.
    - *EC2 Command & Control*: Simulating workload beaconing to known malicious IPs.
    - *Credential Misuse*: Valid credentials reused from an unusual IP to read sensitive data.
  - **Analytics (`/analytics`)**: MTTD (Mean Time To Detect), MTTC (Mean Time To Contain), false-positive rates, and detection coverage heatmaps.
  - **Audit Log (`/audit`)**: Tamper-evident ledger detailing every agent handoff and human analyst decision.

---

## 📂 Project Structure

```text
AgentSOC-Security-Operations-Center/
├── backend/               # FastAPI backend (the real backend) — see "Backend" below
│   ├── app/               # api/ domain/ database/ simulator/ services/ tools/ agents/ llm/ knowledge/
│   └── tests/             # pytest suite
├── config/                # Reference data (MITRE ATT&CK mapping, compliance rules)
├── artifacts/
│   ├── agentsoc/          # Frontend application (React 19, Vite, Tailwind CSS, Lucide icons, Recharts)
│   ├── api-server/        # Express 5 template (unused; not the AgentSOC backend)
│   └── mockup-sandbox/    # Component mockup environment
├── lib/
│   ├── api-client-react/  # Auto-generated React Query hooks
│   ├── api-spec/          # OpenAPI 3.0 specification & Orval codegen configuration
│   ├── api-zod/           # Auto-generated Zod schema validators
│   └── db/                # PostgreSQL schema definitions and Drizzle ORM client
├── scripts/               # Workspace helper scripts
├── package.json           # Workspace root scripts and dependencies
├── pnpm-workspace.yaml    # Workspace definition & dependency overrides
└── README.md              # Project documentation and guide
```

---

## 🛠️ Prerequisites

- **Node.js**: v20 or v24+ ([Download Node.js](https://nodejs.org/))
- **Package Manager**: [pnpm](https://pnpm.io/) (v9+) or `npm` (v10+)

> **Windows Tip**: If `pnpm` is not installed globally, you can install it via:
> ```powershell
> npm install -g pnpm
> ```
> Alternatively, you can prefix commands with `npx pnpm`.

---

## 🚀 Commands to Run

### 1. Install Dependencies

In the root directory of the repository (`AgentSOC-Security-Operations-Center`):

```bash
pnpm install
```
*(Or `npx pnpm install`)*

---

### 2. Run the Frontend (AgentSOC Dashboard)

The dashboard talks to the FastAPI backend through `/api` (the Vite dev server proxies it to
`http://127.0.0.1:8000`). If the backend is not running it falls back to **demo mode** with
bundled simulated data, so you can still explore every view. The top bar shows
`LIVE BACKEND` or `DEMO DATA`.

From the root directory, run:

```bash
npx pnpm run dev
```
*(Or `pnpm run dev` if pnpm is installed in your system PATH)*

Alternatively, you can run directly with Vite from the agentsoc folder:
```bash
cd artifacts/agentsoc
npx vite
```

Once started, open your browser at:
👉 **`http://localhost:3000/`**

---

### 3. Run the Backend (FastAPI)

Requires Python 3.11+. No database server, AWS account or LLM is needed: data is stored in
a local SQLite file (`backend/agentsoc.db`) and the cloud is simulated in memory.

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env              # optional; every setting has a default
python -m uvicorn app.main:app --reload --port 8000
python -m pytest                    # run the tests
```

API docs: http://127.0.0.1:8000/docs. Main endpoints (all under `/api`):
`GET healthz, events, events/stats, events/{id}, incidents, incidents/{id}, agents, tools,
audit, approvals, cloud/state, simulation/scenarios` and
`POST simulation/run, simulation/reset, cloud/reset, cloud/actions`.

To use PostgreSQL instead of SQLite, set `DATABASE_URL=postgresql://...` in `backend/.env`
and `pip install psycopg2-binary`.

> Implemented: the **Monitor Agent** (deterministic, read-only) and the **Triage Agent**
> (local LLM behind strict validation, read-only). Running a scenario stores events; the
> Monitor turns them into incidents; Triage prioritizes an incident when you run it.
> Investigator, Compliance and Remediation are not implemented yet. Containment actions only run through the
> controlled tool layer (`backend/app/tools/`), never as arbitrary commands, and never
> against real AWS.

#### Monitor Agent

Pipeline (`backend/app/agents/monitor/`): validate → normalize → fingerprint → deduplicate
→ correlate → enrich → incident decision → create/update incident → audit → `AgentResult`.
Every threshold lives in `config/monitor_rules.yaml`.

```bash
# 1. generate events
curl -X POST http://127.0.0.1:8000/api/simulation/run -H "Content-Type: application/json" -d "{\"scenario\": \"iam_privilege_escalation\"}"
# 2. process them (no body = every event the Monitor has not processed yet)
curl -X POST http://127.0.0.1:8000/api/agents/monitor/run -H "Content-Type: application/json" -d "{}"
# 3. inspect
curl http://127.0.0.1:8000/api/incidents
```

Optional request fields: `event_ids`, `events` (raw SecurityEvent / CloudTrail / VPC Flow
Log / GuardDuty / Security Hub records to ingest), `time_window_minutes`, `limit`.
`POST /api/simulation/run` also accepts `"run_monitor": true` to do steps 1+2 at once.

#### Triage Agent (local LLM via Ollama)

```bash
ollama pull qwen3:4b          # once; any model works, set LLM_MODEL
curl http://127.0.0.1:8000/api/llm/status
curl -X POST http://127.0.0.1:8000/api/agents/triage/run -H "Content-Type: application/json" -d "{\"incident_id\": \"INC-...\"}"
```

Pipeline (`backend/app/agents/triage/`): incident → read-only evidence (tools, as Triage) →
bounded, redacted JSON context → LLM (text only, JSON-schema constrained) → Pydantic
`TriageDecision` → semantic + policy checks (`config/triage_rules.yaml`, one repair attempt) →
incident update → audit → `AgentResult`. If the LLM is unavailable the run fails cleanly
(`outcome: llm_unavailable`) and the incident is unchanged; a deterministic
`rule_based_fallback` is used only if the request sets `"allow_rule_based_fallback": true`.
Tests never need Ollama (they use `MockLLMProvider`).

---

### 4. Build for Production

To perform full TypeScript type checking and bundle all packages:

```bash
pnpm run build
```

Or build just the frontend bundle:

```bash
pnpm --filter @workspace/agentsoc build
```
*The compiled assets will be in `artifacts/agentsoc/dist/public`.*

---

## ⚙️ Environment Variables

The frontend works without any environment variables, but supports the following overrides:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | Local port for the Vite dev server | `3000` |
| `BASE_PATH` | Base URL path for routing | `/` |
| `VITE_API_URL` | Backend API base URL | `/api` *(proxied in dev)* |
| `VITE_DEMO_MODE` | `true` forces demo data even if a backend is reachable | `false` |
| `AGENTSOC_API_TARGET` | Where the Vite dev proxy sends `/api` | `http://127.0.0.1:8000` |

Backend settings (`DATABASE_URL`, `BACKEND_HOST`, `BACKEND_PORT`, `LLM_*`, ...) are documented
in `backend/.env.example`.

---

## 🧪 Common Workflows

- **Run an Attack Simulation**:
  Navigate to **Attack Simulator** in the sidebar, select **IAM privilege escalation**, and click to trigger. With the backend running, 4 events are stored and the simulated cloud changes (Step 1); then click **Run Monitor Agent on these 4 events** (Step 2) to create the incident, then **Run Triage Agent** (Step 3; needs Ollama). In demo mode, a sample incident `INC-005` is created.
- **Investigate an Incident**:
  Go to **Incidents** (`/incidents`), click `INC-001`, and inspect the attack timeline, agent reasoning trace, and forensic evidence.
- **Approve or Reject Containment**:
  Visit **Approval Center** (`/approvals`) to review pending actions. Click **Approve** or **Reject** to write an entry directly into the **Audit Log**.
