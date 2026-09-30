# 🛡️ AgentSOC — Autonomous Cloud Security Operations Center

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%20%7C%203.13-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/Frontend-React%2019-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Bundler-Vite%207-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev/)
[![TypeScript](https://img.shields.io/badge/Language-TypeScript%205.9-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Styling-Tailwind%20CSS%204-06B6D4.svg?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Ollama](https://img.shields.io/badge/Local%20LLM-Ollama%20(qwen3:4b)-white.svg?logo=ollama&logoColor=black)](https://ollama.ai/)
[![Tests](https://img.shields.io/badge/pytest-564%20passed-brightgreen.svg?logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **AgentSOC** is a simulated autonomous cloud security operations center designed for investigating AWS threats, orchestrating multi-agent investigations, enforcing human-in-the-loop remediation approvals, and maintaining an immutable decision audit trail — with **zero real AWS costs or risks**.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture & Multi-Agent Pipeline](#-architecture--multi-agent-pipeline)
- [Command Center Dashboard Views](#-command-center-dashboard-views)
- [Project Monorepo Structure](#-project-monorepo-structure)
- [Prerequisites](#-prerequisites)
- [Quick Start Guide](#-quick-start-guide)
  - [Option A: Full Stack (Backend + Frontend + Local LLM)](#option-a-full-stack-backend--frontend--local-llm-recommended)
  - [Option B: Frontend Only (Zero-Config Demo Mode)](#option-b-frontend-only-zero-config-demo-mode)
- [Detailed Run Commands](#-detailed-run-commands)
  - [1. Backend Setup & Run (FastAPI)](#1-backend-setup--run-fastapi)
  - [2. Frontend Setup & Run (Vite + React)](#2-frontend-setup--run-vite--react)
  - [3. Local LLM Setup (Ollama)](#3-local-llm-setup-ollama)
  - [4. ML Threat Predictor Training](#4-ml-threat-predictor-training)
- [End-to-End Simulation Walkthrough](#-end-to-end-simulation-walkthrough)
  - [Interactive Web UI Walkthrough](#interactive-web-ui-walkthrough)
  - [Automated API / cURL Walkthrough](#automated-api--curl-walkthrough)
- [Safety, Guardrails & Containment Kill Switch](#-safety-guardrails--containment-kill-switch)
- [Configuration & Environment Variables](#-configuration--environment-variables)
  - [Backend Configuration (`backend/.env`)](#backend-configuration-backendenv)
  - [Frontend Configuration (`artifacts/agentsoc`)](#frontend-configuration-artifactsagentsoc)
- [Testing & Quality Assurance](#-testing--quality-assurance)
- [Troubleshooting & FAQ](#-troubleshooting--faq)

---

## 🌐 Overview

Modern cloud environments produce thousands of security events every minute. Human security analysts face alert fatigue, while fully autonomous remediation without oversight risks accidental production outages.

**AgentSOC solves this by pairing autonomous agent intelligence with strict human-in-the-loop governance:**
1. **Telemetry Ingestion**: Monitors CloudTrail, VPC Flow Logs, GuardDuty, and Security Hub events in a simulated AWS environment.
2. **Multi-Agent Pipeline**: Specialized agents handle event normalization, risk triage, forensic blast-radius investigation, compliance mapping, and remediation planning.
3. **Strict Human Gate**: Remediation proposals are never executed automatically. An analyst must review the action, rationale, and diff before authorization.
4. **Deterministic Verification**: An independent verification agent audits the simulated cloud state post-execution to verify containment success.
5. **Feedback & Learning**: Structured post-mortems and ML threat classification continuously refine decision-support accuracy.

---

## 🤖 Architecture & Multi-Agent Pipeline

AgentSOC features a 7-stage agent lifecycle accompanied by a Machine Learning Threat Predictor:

```mermaid
flowchart TD
    subgraph Ingestion
        A[Simulated Cloud Events / Telemetry] --> B[🔍 Monitor Agent]
    end

    subgraph Investigation & Assessment
        B -->|Normalized Incident| C[⚖️ Triage Agent]
        C -->|Prioritized Incident| D[🔎 Investigator Agent]
        D -->|Attack Graph & MITRE Mapping| E[🛡️ Compliance Agent]
    end

    subgraph Remediation & Verification
        E -->|Violations & Controls| F[⚡ Remediation Agent]
        F -->|Proposal Only| G{👤 Human Analyst Approval Gate}
        G -->|Approved + Kill Switch Enabled| H[⚙️ ToolExecutor]
        G -->|Rejected / Cancelled| I[Audit Log Record]
        H -->|Simulated Cloud Action| J[Simulated Cloud State]
        J --> K[✅ Verification Agent]
        K --> L[📊 Feedback & Learning Service]
    end

    subgraph Decision Support
        M[🤖 ML Threat Predictor (Random Forest)] -.->|Threat Classification| B
        M -.->|Confidence Signal| C
    end
```

### Agent Breakdown

| Agent / Service | Intelligence Mode | Role & Capabilities | Guardrails & Rules |
| :--- | :--- | :--- | :--- |
| **🔍 Monitor Agent** | Deterministic | Validates, normalizes, deduplicates, and correlates multi-source cloud telemetry into high-confidence incidents. | Thresholds configured in `config/monitor_rules.yaml`. Read-only. |
| **⚖️ Triage Agent** | Local LLM / Rule Fallback | Assesses environmental risk, correlates identity chains, and prioritizes incidents (P1–P4). | JSON-schema constrained Pydantic model (`config/triage_rules.yaml`). Fallback when LLM offline. |
| **🔎 Investigator Agent** | Local LLM + Knowledge Base | Deep-dives into telemetry, catalogs evidence (EV/PR/RS/SF), constructs attack timelines, and maps to MITRE ATT&CK techniques (e.g. T1098). | Context window bounded; mappings validated against `config/mitre_mapping.yaml` and `config/investigator_rules.yaml`. |
| **🛡️ Compliance Agent** | Local LLM + Rule Engine | Maps incident findings to security frameworks: **NIST CSF**, **ISO 27001**, **SOC 2**, and **CIS Controls**. | Validated against `config/compliance_mapping.yaml` and `config/compliance_policy.yaml`. No arbitrary statutes. |
| **⚡ Remediation Agent** | Local LLM Reasoning | Proposes targeted containment actions (`disable_access_key`, `remove_admin_privileges`, `isolate_instance`, `make_bucket_private`). | **Planning only**. Gated behind strict human approval. Evaluated against `config/remediation_policy.yaml`. |
| **✅ Verification Agent** | Deterministic | Compares **BEFORE**, **EXPECTED**, and **ACTUAL** cloud states after remediation executes. | Read-only. Does not trust execution logs; directly reads resource state. Never executes or alters cloud state. |
| **📊 Feedback & Learning** | Deterministic Service | Generates structured learning records (`successful_response`, `failed_response`, `partial_response`), tracks regressions, and captures human feedback. | Rules defined in `config/feedback_rules.yaml`. Does not store credentials or raw prompts. |
| **🤖 ML Threat Predictor** | Random Forest (scikit-learn) | Classifies event groups into threat classes (`IAM_PRIVILEGE_ESCALATION`, `CREDENTIAL_MISUSE`, `S3_UNAUTHORIZED_ACCESS`, etc.). | Operates as decision support; ML alone cannot open incidents or execute actions. |

---

## 🖥️ Command Center Dashboard Views

The frontend dashboard provides a command center with responsive dark mode and real-time state:

- **Overview (`/`)**: Threat activity timeline charts, incident severity breakdown, agent response throughput, and AWS security posture score (e.g., `87/100`).
- **Incidents (`/incidents`)**: Filterable incident triage queue with detailed forensic drawer:
  - Attack timeline reconstruction
  - Agent decision traces & reasoning logs
  - MITRE ATT&CK technique tags
  - Blast-radius summary and affected cloud resources
- **Security Events (`/events`)**: Normalized security telemetry stream with multi-field filtering and single-click CSV export.
- **Agent Network (`/agents`)**: Directory of all 7 agents and services displaying input/output schemas, allowed tools, execution latency, and success metrics.
- **Approval Center (`/approvals`)**: Centralized human-in-the-loop authorization inbox. Analysts review planned containment actions, affected resources, and risk rationales before single-click **Approve** or **Reject**.
- **Cloud Environment (`/cloud`)**: Visual inventory of simulated AWS resources (IAM Roles/Users, S3 Buckets, EC2 Workloads) with live posture badges.
- **Attack Simulator (`/simulator`)**: One-click sandboxed threat emulation scenarios:
  1. *IAM Privilege Escalation*: `AttachUserPolicy` on a non-admin CI principal.
  2. *Public S3 Exposure*: Making private financial export buckets publicly readable.
  3. *EC2 Command & Control*: Simulating outbound C2 beaconing to high-risk IP addresses.
  4. *Credential Misuse*: Stolen developer keys reused from an unusual geolocation.
- **Analytics (`/analytics`)**: MTTD (Mean Time To Detect), MTTC (Mean Time To Contain), false-positive distributions, and MITRE matrix coverage.
- **Audit Log (`/audit`)**: Immutable, tamper-evident audit ledger capturing every agent handoff, LLM proposal, and human decision.

---

## 📂 Project Monorepo Structure

```text
AgentSOC-Security-Operations-Center/
├── backend/                         # Python FastAPI Backend
│   ├── app/
│   │   ├── agents/                  # 7 Agent implementations (Monitor, Triage, Investigator, etc.)
│   │   ├── api/                     # REST API routes and OpenAPI specs
│   │   ├── database/                # SQLAlchemy models and SQLite/PostgreSQL connection
│   │   ├── domain/                  # Pydantic schemas (Incidents, Events, Approvals, Audit)
│   │   ├── ml/                      # Random Forest model, training pipeline, and feature extraction
│   │   ├── simulator/               # In-memory AWS cloud simulator & attack generators
│   │   ├── tools/                   # Tool registry and safe ToolExecutor layer
│   │   ├── config.py                # App settings and environment loader
│   │   └── main.py                  # FastAPI application factory
│   ├── tests/                       # 560+ pytest suite covering all agents, tools, and APIs
│   ├── .env.example                 # Backend environment variable template
│   └── requirements.txt             # Python dependencies (FastAPI, uvicorn, scikit-learn, etc.)
├── artifacts/
│   └── agentsoc/                    # React 19 Frontend Dashboard
│       ├── src/
│       │   ├── components/          # Reusable UI component library (Radix UI, charts, badges)
│       │   ├── lib/
│       │   │   └── api.ts           # Dual-mode API client (live backend + demo fallback)
│       │   ├── App.tsx              # Router, state management, and page layouts
│       │   ├── data.ts              # Typed seed data for standalone demo mode
│       │   └── index.css            # Tailwind CSS 4 theme and custom styles
│       ├── vite.config.ts           # Vite 7 configuration with API reverse proxy
│       └── package.json             # Frontend package configuration
├── config/                          # Declarative SOC policy and rules (YAML)
│   ├── compliance_mapping.yaml      # NIST, ISO, SOC 2, CIS control mappings
│   ├── compliance_policy.yaml       # Compliance assessment rules
│   ├── investigator_rules.yaml      # Blast radius and forensic evidence rules
│   ├── mitre_mapping.yaml           # MITRE ATT&CK technique definitions
│   ├── ml_config.yaml               # Threat predictor model hyperparameters
│   ├── monitor_rules.yaml           # Ingestion, deduplication, and correlation thresholds
│   ├── remediation_policy.yaml      # Allow-listed containment actions and approval TTLs
│   ├── triage_rules.yaml            # Severity scoring and deterministic triage fallback
│   └── verification_rules.yaml      # Post-remediation verification assertions
├── package.json                     # Monorepo root scripts
├── pnpm-workspace.yaml              # pnpm workspace definition
└── README.md                        # Documentation
```

---

## 🛠️ Prerequisites

Before running the project, ensure you have the following installed:

| Tool | Version Requirement | Purpose |
| :--- | :--- | :--- |
| **Node.js** | `v20.x` or `v24.x+` | Runs the frontend development server and tooling |
| **pnpm** | `v9.x+` (or `npx pnpm`) | Monorepo package manager |
| **Python** | `3.11+` or `3.13` | Runs the FastAPI backend, agent pipeline, and ML engine |
| **Ollama** *(Optional)* | Latest | Local LLM inference (`qwen3:4b` recommended) |

> **Windows Note**: If `pnpm` is not in your system `PATH`, you can use `npx pnpm` for all commands or install it globally with `npm install -g pnpm`.

---

## ⚡ Quick Start Guide

### Option A: Full Stack (Backend + Frontend + Local LLM) *(Recommended)*

Run the complete autonomous SOC with live telemetry, active agent pipeline, and interactive dashboard:

```bash
# Terminal 1: Start Backend (FastAPI on http://127.0.0.1:8000)
cd backend
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux/macOS:
# source .venv/bin/activate
pip install -r requirements.txt
python -m app.ml.train --activate
python -m uvicorn app.main:app --reload --port 8000

# Terminal 2: Start Frontend (Vite on http://localhost:3000)
# (from the repository root)
npx pnpm install
npx pnpm run dev

# Terminal 3 (Optional): Start Local LLM
ollama pull qwen3:4b
```

👉 Open **`http://localhost:3000/`** in your browser. The top header will display **`LIVE BACKEND`**.

---

### Option B: Frontend Only (Zero-Config Demo Mode)

If you just want to preview and explore the UI without setting up Python:

```bash
# In the repository root:
npx pnpm install
npx pnpm run dev
```

👉 Open **`http://localhost:3000/`**. The dashboard automatically detects that the backend is offline and boots into **`DEMO DATA`** mode with fully populated incidents, attack timelines, approvals, and metrics.

---

## 📖 Detailed Run Commands

### 1. Backend Setup & Run (FastAPI)

The backend uses a local SQLite database (`backend/agentsoc.db`) by default. No PostgreSQL server or AWS credentials are required.

#### Step 1: Navigate to the backend directory
```bash
cd backend
```

#### Step 2: Create and activate a Python virtual environment
- **Windows (PowerShell)**:
  ```powershell
  python -m venv .venv
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .venv\Scripts\Activate.ps1
  ```
- **Windows (Command Prompt)**:
  ```cmd
  python -m venv .venv
  .venv\Scripts\activate.bat
  ```
- **Linux / macOS (Bash/Zsh)**:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

#### Step 3: Install backend dependencies
```bash
pip install -r requirements.txt
```

#### Step 4: Configure environment (optional)
```bash
# Windows:
copy .env.example .env
# Linux / macOS:
cp .env.example .env
```
*(Every variable has safe local defaults; editing `.env` is completely optional).*

#### Step 5: Train and activate the ML Threat Model
```bash
python -m app.ml.train --activate
```
*This generates synthetic training samples from the cloud simulator and saves an active Random Forest classifier to `backend/ml_models/` in ~2 seconds.*

#### Step 6: Start the FastAPI server
```bash
python -m uvicorn app.main:app --reload --port 8000
```
*Or using the entrypoint module:*
```bash
python -m app
```

- **API Base URL**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **Health Check**: `http://127.0.0.1:8000/api/healthz`

---

### 2. Frontend Setup & Run (Vite + React)

The frontend is a Vite + React application configured with an automatic reverse proxy forwarding `/api/*` requests to `http://127.0.0.1:8000`.

#### Step 1: Install workspace packages
From the repository root:
```bash
pnpm install
```
*(Or `npx pnpm install`)*

#### Step 2: Launch the development server
```bash
pnpm run dev
```
*(Or `npx pnpm run dev`)*

Alternatively, launch directly from the frontend directory:
```bash
cd artifacts/agentsoc
npx vite
```

- **Dashboard URL**: `http://localhost:3000/`
- **Network Access**: Accessible on `0.0.0.0:3000`

---

### 3. Local LLM Setup (Ollama)

AgentSOC uses [Ollama](https://ollama.ai/) for local, private inference during Triage, Investigation, Compliance, and Remediation planning:

1. **Install Ollama**: Download from [ollama.ai](https://ollama.ai/download).
2. **Pull the recommended model**:
   ```bash
   ollama pull qwen3:4b
   ```
   *(You can also use `llama3.2:3b`, `mistral`, or any other model by setting `LLM_MODEL` in `backend/.env`).*
3. **Verify LLM Connectivity**:
   ```bash
   curl http://127.0.0.1:8000/api/llm/status
   ```
   Expected response: `{"status": "ready", "provider": "ollama", "model": "qwen3:4b"}`.

> **Offline / Fallback Support**: If Ollama is not running, AgentSOC automatically uses deterministic rule-based triage (`config/triage_rules.yaml`) when fallback is requested, so the system remains fully testable without an LLM.

---

### 4. ML Threat Predictor Training

The Random Forest model classifies events into 6 incident categories:

```bash
cd backend
# Train from simulator data and immediately set as the active inference model:
python -m app.ml.train --activate

# Inspect model status via API:
curl http://127.0.0.1:8000/api/ml/status
```

---

## 🎮 End-to-End Simulation Walkthrough

### Interactive Web UI Walkthrough

1. Open **`http://localhost:3000/simulator`** in your browser.
2. Under **Threat Scenarios**, click **IAM Privilege Escalation** (or Public S3 Exposure).
3. Follow the guided 7-step pipeline directly on screen:
   - **Step 1: Emulate Attack**: Generates realistic CloudTrail events and alters the simulated AWS cloud state.
   - **Step 2: Run Monitor Agent**: Normalizes events and opens a new Incident.
   - **Step 3: Run Triage Agent**: Correlates identity and assigns incident priority.
   - **Step 4: Run Investigator Agent**: Catalogs evidence and identifies MITRE ATT&CK technique (e.g. `T1098`).
   - **Step 5: Run Compliance Agent**: Audits against NIST CSF and CIS Controls.
   - **Step 6: Run Remediation Agent**: Proposes a containment action and creates a pending approval card.
   - **Step 7: Approve & Verify**: Navigate to `/approvals`, review the action, and click **Approve**. Once executed, click **Run Verification** to verify the cloud state has been restored.

---

### Automated API / cURL Walkthrough

You can execute the entire multi-agent cycle programmatically from your terminal:

```bash
# 1. Trigger an attack simulation
curl -X POST http://127.0.0.1:8000/api/simulation/run \
  -H "Content-Type: application/json" \
  -d '{"scenario": "iam_privilege_escalation"}'

# 2. Run Monitor Agent on newly generated events
curl -X POST http://127.0.0.1:8000/api/agents/monitor/run \
  -H "Content-Type: application/json" \
  -d '{}'

# 3. List incidents to get the new Incident ID (e.g., INC-001)
curl http://127.0.0.1:8000/api/incidents

# 4. Run Triage Agent
curl -X POST http://127.0.0.1:8000/api/agents/triage/run \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "INC-001"}'

# 5. Run Investigator Agent
curl -X POST http://127.0.0.1:8000/api/agents/investigator/run \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "INC-001"}'

# 6. Run Compliance Agent
curl -X POST http://127.0.0.1:8000/api/agents/compliance/run \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "INC-001"}'

# 7. Run Remediation Agent (proposes plan, creates pending approval)
curl -X POST http://127.0.0.1:8000/api/agents/remediation/run \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "INC-001"}'

# 8. Check pending approvals
curl http://127.0.0.1:8000/api/approvals?status=pending

# 9. Human approves the action (replace APR-001 with your approval ID)
curl -X POST http://127.0.0.1:8000/api/approvals/APR-001/approve

# 10. Run Verification Agent to confirm resource state restoration
curl -X POST http://127.0.0.1:8000/api/agents/verification/run \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "INC-001"}'
```

---

## 🔒 Safety, Guardrails & Containment Kill Switch

AgentSOC adheres to defensive security-engineering principles:

1. **Simulated Cloud Boundary**: The system interacts strictly with `backend/app/simulator/cloud.py`. **It never connects to real AWS APIs or charges cloud infrastructure bills.**
2. **Remediation Kill Switch (`AGENT_ACTIONS_ENABLED`)**:
   - Default: `false`.
   - While disabled, approvals are safely recorded in the audit trail, but actual execution against the simulated cloud is blocked (`outcome: actions_disabled`).
   - Set `AGENT_ACTIONS_ENABLED=true` in `backend/.env` to allow approved actions to execute.
3. **Allow-Listed Actions Only**: The Remediation Agent can only ever propose one of four strictly audited actions:
   - `disable_access_key`
   - `remove_admin_privileges`
   - `isolate_instance`
   - `make_bucket_private`
4. **Stale Plan Detection**: If the cloud resource state changes between when a plan is drafted and when an analyst approves it, execution is aborted with `stale_remediation_plan`.
5. **Read-Only Independent Verification**: The Verification Agent has zero action permissions; it inspects resource state objectively without trusting execution return codes.

---

## ⚙️ Configuration & Environment Variables

### Backend Configuration (`backend/.env`)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DATABASE_URL` | SQLAlchemy database URL. Supports SQLite or PostgreSQL. | `sqlite:///backend/agentsoc.db` |
| `BACKEND_HOST` | Host interface for FastAPI / Uvicorn server | `127.0.0.1` |
| `BACKEND_PORT` | Port for FastAPI backend | `8000` |
| `CORS_ORIGINS` | Comma-separated allowed frontend origins | `http://localhost:3000,http://127.0.0.1:3000` |
| `LOG_LEVEL` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO` |
| `LLM_PROVIDER` | Reasoning provider (`ollama` or `none`) | `ollama` |
| `LLM_MODEL` | Ollama model tag | `qwen3:4b` |
| `OLLAMA_BASE_URL` | Base endpoint for Ollama daemon | `http://localhost:11434` |
| `OLLAMA_NUM_CTX` | Context window size in tokens | `8192` |
| `AGENT_ACTIONS_ENABLED` | **Kill switch**: set to `true` to allow executing approved actions | `false` |
| `ML_MODEL_DIR` | Custom directory for trained model artifacts | `backend/ml_models` |

### Frontend Configuration (`artifacts/agentsoc`)

Set via environment variables or `.env`:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | Local port for the Vite dev server | `3000` |
| `BASE_PATH` | Base URL path for routing | `/` |
| `VITE_API_URL` | API base path | `/api` *(proxied to backend in dev)* |
| `VITE_DEMO_MODE` | Set to `true` to force demo data even when backend is running | `false` |
| `AGENTSOC_API_TARGET` | Destination backend URL for the Vite `/api` proxy | `http://127.0.0.1:8000` |

---

## 🧪 Testing & Quality Assurance

### Run Backend Tests (pytest)

The backend includes a test suite covering the event pipeline, agents, schemas, tools, ML models, and API endpoints:

```bash
cd backend
.venv\Scripts\Activate.ps1   # Linux/macOS: source .venv/bin/activate
python -m pytest
```

To run a specific test suite:
```bash
python -m pytest tests/test_monitor_agent.py
python -m pytest tests/test_remediation.py
python -m pytest tests/test_verification.py
```

### Run Frontend Typecheck & Build

```bash
# Typecheck entire workspace
pnpm run typecheck

# Build frontend production bundle
pnpm --filter @workspace/agentsoc build
```
*Compiled static production assets are emitted to `artifacts/agentsoc/dist/public`.*

---

## ❓ Troubleshooting & FAQ

### 1. `pnpm: command not found` on Windows
Use `npx pnpm` instead of `pnpm`, or install `pnpm` globally:
```powershell
npm install -g pnpm
```

### 2. PowerShell execution policy error when activating `.venv`
If you see `execution of scripts is disabled on this system`, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

### 3. Frontend shows `DEMO DATA` badge instead of `LIVE BACKEND`
1. Ensure the FastAPI backend is running on `http://127.0.0.1:8000`. Test with:
   ```bash
   curl http://127.0.0.1:8000/api/healthz
   ```
2. Verify that `AGENTSOC_API_TARGET` is pointing to `http://127.0.0.1:8000`.
3. Ensure `VITE_DEMO_MODE` is not set to `true`.

### 4. Triage or Remediation agent shows `LLM Unavailable`
Ensure Ollama is running (`ollama serve`) and the model is downloaded:
```bash
ollama pull qwen3:4b
```
If you do not have Ollama installed, test runs and API calls can use deterministic rule fallbacks by passing `"allow_rule_based_fallback": true`.

### 5. Containment approvals say `actions_disabled`
This is expected behavior from the safety kill switch. To allow actions to modify the simulated cloud state, set in `backend/.env`:
```ini
AGENT_ACTIONS_ENABLED=true
```
Then restart the backend and re-trigger execution via `POST /api/approvals/{id}/execute` or through the UI.

---

<div align="center">
  <sub>Built for cloud security engineers, SOC analysts, and autonomous agent researchers.</sub>
</div>
