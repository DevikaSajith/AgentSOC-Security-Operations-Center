# AgentSOC Security Operations Center

AgentSOC is a simulated autonomous cloud security operations center for investigating AWS threats, approving remediation, and reviewing agent decisions.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/agentsoc/src/App.tsx` — route-driven SOC shell and interactive demo flows
- `artifacts/agentsoc/src/data.ts` — typed demo incidents, events, agents, approvals, cloud resources, and audit entries
- `artifacts/agentsoc/src/lib/api.ts` — backend-ready API seam with demo fallback
- `artifacts/agentsoc/src/index.css` — AgentSOC visual system and responsive layout
- `artifacts/api-server` — shared Express API service for future FastAPI-compatible endpoints

## Architecture decisions

- The first build is frontend-first and remains fully usable without a running backend.
- Demo state lives in React state so the simulator, approval center, incident details, and audit log update together during a presentation.
- `src/lib/api.ts` checks `VITE_API_URL` or `NEXT_PUBLIC_API_URL` when present and falls back to the typed demo data when unavailable.

## Product

AgentSOC presents a command-center view of a simulated AWS environment. Analysts can search and filter incidents and events, inspect attack timelines, follow the five-agent response pipeline, run controlled attack scenarios, approve or reject remediation, and expand the audit trail.

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

_Populate as you build — sharp edges, "always run X before Y" rules._

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
