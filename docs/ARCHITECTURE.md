# CyberMap AI — Architecture

> **Status:** Phases 1–10 complete. All 8 modules done; see
> `docs/ROADMAP.md` for the per-phase evidence.

## 1. What CyberMap AI is

An AI-powered vulnerability intelligence platform. It collects **publicly
available** vulnerability intelligence (NVD CVE records, CISA Known
Exploited Vulnerabilities, FIRST EPSS scores, MITRE ATT&CK techniques and
MITRE CWE weaknesses), stores it in a normalized database, connects
related entities in a knowledge graph, and helps researchers understand
vulnerabilities through AI-powered analysis — with a fully functional
non-AI fallback mode when no AI provider is configured.

**Own identity.** CyberMap AI is an original implementation. It is not a
copy of any other product's branding, source code, text or design.

**Tagline:** *Understand Vulnerabilities. Connect Threats. Think Like a
Security Researcher.*

## 2. Technology stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 16 (App Router) + TypeScript + React 19 + Tailwind CSS 4 |
| Server state | TanStack Query |
| Validation | Zod |
| Charts | Recharts (Phase 5) |
| Graph | React Flow (Phase 7) |
| Backend | Python 3.12, FastAPI, Pydantic, SQLAlchemy 2 |
| Migrations | Alembic (Phase 3) |
| Database | PostgreSQL 16 + pgvector |
| Cache / jobs | Redis 7 |
| AI | Provider-independent LLM adapters + RAG over pgvector (Phase 6) |
| Tests | pytest (backend), Playwright (E2E, Phase 9) |
| Infra | Docker, Docker Compose |

**Developer machine:** ASUS TUF F16, NVIDIA RTX 3050. No locally hosted
LLM is required — AI runs through external provider adapters, and the
platform works fully without any provider configured.

## 3. System diagram

```
                         ┌──────────────────────┐
                         │  Browser (researcher)│
                         └──────────┬───────────┘
                                    │ HTTPS
                         ┌──────────▼───────────┐
                         │  Frontend            │
                         │  Next.js App Router  │
                         │  TS + Tailwind       │
                         │  TanStack Query      │
                         └──────────┬───────────┘
                                    │ REST / JSON
                         ┌──────────▼───────────┐
                         │  Backend             │
                         │  FastAPI + Pydantic  │
                         │  app/main.py         │
                         │  app/api/v1/*        │
                         └─┬────────┬───────┬───┘
                           │        │       │
              ┌────────────▼─┐ ┌────▼────┐ ┌▼──────────────┐
              │ PostgreSQL   │ │ Redis   │ │ AI adapters   │
              │ + pgvector   │ │ cache + │ │ OpenAI/Groq/  │
              │ (vulns,      │ │ jobs    │ │ Gemini +      │
              │  users,      │ │         │ │ non-AI        │
              │  graph, RAG) │ │         │ │ fallback      │
              └──────────────┘ └─────────┘ └───────────────┘
```

### How a request flows

```
Browser ──► Next.js page (Server Component) ──► fetch to FastAPI
        ──► route handler ──► service layer ──► SQLAlchemy repository
        ──► PostgreSQL (or Redis cache) ──► JSON response
        ──► React component renders (loading / empty / error states)
```

### How ingestion flows (Phase 4)

```
Official source API ──► ingestion connector (validate + normalize)
        ──► dedup / safe upsert ──► PostgreSQL
        ──► ingestion_jobs row (status, counts, errors)
        ──► sync-status shown on the dashboard
```

Ingestion never scrapes websites when an official API or downloadable
catalog exists. Each connector respects rate limits and retries with
exponential backoff.

## 4. Module map

| # | Module | Phase | Status |
|---|---|---|---|
| 1 | Intelligence Dashboard | 5 | ✅ Done |
| 2 | Vulnerability Explorer | 5 | ✅ Done |
| 3 | AI Vulnerability Analyst | 6 | ✅ Done |
| 4 | Attack Knowledge Graph | 7 | ✅ Done |
| 5 | AI Research Assistant | 6 | ✅ Done |
| 6 | Threat Intelligence Center | 5 | ✅ Done |
| 7 | Research Workspace | 8 | ✅ Done |
| 8 | Security Learning Center | 8 | ✅ Done |

## 5. Backend layout

```
backend/
  app/
    main.py          # app factory (create_app), CORS, routers
    core/            # config (env), database engine, security helpers
    api/v1/          # versioned routers: health, auth, dashboard,
                     # vulnerabilities, cwe, attack-techniques,
                     # intelligence, ai, graph, research, ingestion, admin
    models/          # SQLAlchemy models (see docs/DATABASE.md)
    schemas/         # Pydantic request/response schemas
    services/        # business logic (one service per domain)
    repositories/    # data access (queries, pagination, filters)
    integrations/    # NVD / KEV / EPSS / MITRE clients
    ingestion/       # connectors + orchestration + sync logging
    ai/              # provider adapters, embeddings, RAG, prompts
    workers/         # background jobs (ingestion scheduler)
    security/        # password hashing, sessions, RBAC, rate limiting
    utils/           # shared helpers
  migrations/        # Alembic (Phase 3)
  tests/             # pytest
```

## 6. Frontend layout

```
frontend/
  app/               # App Router pages: dashboard, vulnerabilities,
                     # vulnerability/[cveId], intelligence, attack-graph,
                     # ai-assistant, research, learning, settings,
                     # login, register
  components/        # reusable UI (cards, tables, charts, graph nodes)
  hooks/             # data hooks (TanStack Query wrappers)
  lib/               # api client, query client, zod schemas
  services/          # typed API calls per domain
  types/             # shared TypeScript types
```

## 7. AI design (Phase 6)

- **Provider-independent adapters.** One interface (`chat`, `embed`),
  one adapter per provider (OpenAI, Groq, Google Gemini). The provider
  is chosen by `AI_PROVIDER` + `AI_MODEL` env vars; keys come only from
  env vars, never from code.
- **RAG.** Vulnerability descriptions, CWE entries and ATT&CK techniques
  are embedded (provider embedding API, or a local sentence-transformer
  when no provider is set — see `docs/AI_PIPELINE.md`) and stored in
  pgvector. Retrieval returns the top-k records with similarity scores;
  the LLM only answers from that grounded context.
- **Non-AI fallback.** When no provider is configured, analysis and chat
  still work: structured summaries built from the database records
  themselves (severity, CWE, KEV/EPSS, references), clearly labelled
  "rule-based summary — no AI provider configured".
- **Safety.** Retrieved external content is treated as untrusted data,
  never as instructions. AI output never invents CVE facts, CVSS or EPSS
  scores — every number comes from the database and is cited. No
  generated commands or payloads are executed.

## 8. Security principles

- Passwords hashed with Argon2 (Phase 3). HTTP-only session cookies.
- Parameterised SQL only (SQLAlchemy). Input validation with Pydantic
  (backend) and Zod (frontend).
- Role-based access: `user` / `researcher` / `admin`. Admin-only
  ingestion endpoints. Users can only access their own research data
  (row-level checks in every repository query).
- Audit logging for auth events, ingestion runs and admin actions.
- No secrets in code, no stack traces leaked to clients, secure CORS
  (explicit origin list, not `*`).
- Full review in `docs/SECURITY.md` (Phase 9).

## 9. Data honesty rules

1. Every statistic on the dashboard comes from the database.
2. Missing data is shown as "unavailable", never as zero risk.
3. Seed data (if ever used) is labelled SEED and never described as
   live intelligence.
4. AI answers distinguish source facts from AI interpretation, and cite
   the records used.

## 10. Environment variables

See `.env.example` at the repo root. The complete list, with defaults
and which phase needs each variable, is documented in
`docs/DEVELOPMENT.md` (Phase 10).
