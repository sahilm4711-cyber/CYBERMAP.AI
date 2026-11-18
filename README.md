# CyberMap AI

**Understand Vulnerabilities. Connect Threats. Think Like a Security Researcher.**

CyberMap AI is an AI-powered vulnerability intelligence platform. It
collects publicly available vulnerability intelligence — NVD CVE records,
CISA Known Exploited Vulnerabilities, FIRST EPSS scores, MITRE ATT&CK
techniques and MITRE CWE weaknesses — stores it in a normalized
database, connects related entities in a knowledge graph, and helps
researchers understand vulnerabilities through AI-powered analysis,
with a fully functional non-AI fallback mode.

> **Current status: Phases 1–10 complete.** All 8 modules are built
> and tested: **197 backend pytest tests passing**, frontend
> `npm run build` clean (14 pages) and `npm run lint` clean, 50 API
> routes live, and the dev database holds live ingested data (50
> CVEs, 984 CWE, 706 techniques, 1782 KEV, 48 EPSS). See
> `docs/TESTING_REPORT.md` for the full verification record — and
> the honest list of what is still unverified (Docker Compose was
> never run in the build VM; no real-browser click-test yet;
> provider-mode AI untested without keys).

## Features (all 8 modules, built)

- **Intelligence Dashboard** — real DB stats only, severity/CWE
  charts, KEV and EPSS views, sync status, date-range filter.
- **Vulnerability Explorer** — search, filter (severity, CWE, CVSS,
  EPSS, vendor, KEV), sort (`newest` / `oldest` / `severity` /
  `cvss` / `epss` / `risk`), pagination, CVE detail pages with
  CVSS, CWE, EPSS, KEV, references and remediation.
- **AI Vulnerability Analyst** — structured 10-section analysis
  with source citations; works with a configured provider
  (OpenAI / Groq / Google Gemini) or fully offline in the
  rule-based fallback mode.
- **Attack Knowledge Graph** — CVE → CWE → ATT&CK → product →
  mitigation, interactive React Flow graph, node expansion and
  search. Graph nodes are public intelligence only.
- **AI Research Assistant** — grounded RAG chat with citations and
  conversation history; retrieved content is treated as untrusted
  data, never instructions.
- **Threat Intelligence Center** — KEV additions, EPSS risk
  ranking, timeline, CVSS vs EPSS vs KEV explained in plain
  language.
- **Research Workspace** — collections, bookmarks, notes, saved
  analyses, CVE comparison, JSON/CSV export — all user-isolated
  (another user's object returns 404, never 403).
- **Security Learning Center** — 9 topics (OWASP Top 10, CWE
  categories, secure coding, …) with related real records from
  the database, clearly separated from the educational text.

## Technology stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 16 (App Router), TypeScript, React 19, Tailwind CSS 4, TanStack Query, Zod, Recharts, React Flow |
| Backend | Python 3.12, FastAPI, Pydantic, SQLAlchemy 2, Alembic |
| Database | PostgreSQL 16 + pgvector (production); SQLite for local dev |
| Cache / jobs | Redis 7 (optional — the app runs without it) |
| AI | Provider-independent adapters (OpenAI / Groq / Google Gemini) + pgvector RAG + non-AI fallback |
| Tests | pytest (197 tests), ESLint, manual E2E smoke walk (23/23) |
| Infra | Docker, Docker Compose (Compose **not yet verified** — see Limitations) |

Developer machine: ASUS TUF F16, NVIDIA RTX 3050. No locally hosted
LLM is required.

## Folder structure

```
cybermap-ai/
├── frontend/          # Next.js App Router + TypeScript + Tailwind
├── backend/           # FastAPI + SQLAlchemy
│   ├── app/           # api, core, models, schemas, services, ...
│   ├── migrations/    # Alembic (0001_initial — all 21 tables)
│   ├── scripts/       # generate_learning_topics.py
│   └── tests/         # pytest — 197 tests
├── infrastructure/docker/
├── docs/              # ARCHITECTURE, DATABASE, ROADMAP, API, ...
├── docker-compose.yml # Full stack — NOT verified in the build VM
├── .env.example
└── README.md
```

## Prerequisites

- Node.js 20+ and npm
- Python 3.12+
- Docker + Docker Compose (for the full stack), **or** run the two
  services directly for development (below)

## Local installation

### Option A — Docker (full stack)

```bash
cp .env.example .env   # fill in your own values
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API + docs: http://localhost:8000/docs

> ⚠️ **Docker Compose has not been verified in the build
> workspace** (no Docker there). It is written and reviewed, but
> the first real run must happen on the developer machine. See
> `docs/DEVELOPMENT.md` §3.

### Option B — run services directly (no Docker, the verified path)

```bash
# Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp ../.env.example ../.env   # fill in your own values
.venv/bin/alembic upgrade head
.venv/bin/python -m uvicorn app.main:app --reload --port 8000

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

The backend defaults to a local SQLite file (`cybermap.db`) when no
`DATABASE_URL` is set, so it runs without Postgres. PostgreSQL +
pgvector is required for real vector search and is the supported
production path. Full setup, environment variables and
troubleshooting: `docs/DEVELOPMENT.md`.

## What works now (Phases 1–10 complete)

- `GET /` — service info
- `GET /health` and `GET /api/v1/health` — status, version,
  environment, database state (real `SELECT 1` check, Phase 9),
  AI mode
- `GET /docs` — interactive Swagger UI (full API reference is in
  `docs/API.md`)
- Auth (`/api/v1/auth`): register, login, logout, `/me`,
  password change — Argon2id hashing, HTTP-only session cookies,
  roles (`user` / `researcher` / `admin`), common-password
  denylist, login rate limiting (10 failed / 15 min → 429),
  CSRF Origin check, audit logging
- Alembic migrations (`backend/migrations/`): initial migration
  creates all 21 tables and seeds roles + data sources
- Ingestion (`/api/v1/ingestion`, admin-only sync): NVD, CISA KEV,
  FIRST EPSS, MITRE ATT&CK + CWE — bounded, rate-limited,
  logged per run
- Dashboard, explorer, intelligence, graph, AI analyst +
  assistant, research workspace, learning center — all live,
  all backed by the database
- Frontend: 14 pages, every page fetching the backend; login,
  register and AI-assistant pages included

## Live data (dev database)

The dev database (`backend/cybermap.db`, **not** committed) holds
live ingested data from the public sources: **50 CVEs, 984 CWE
entries, 706 ATT&CK techniques, 1782 KEV entries, 48 EPSS
scores**. The dashboard, explorer, graph and AI features all run
against this data. A fresh clone starts with an empty database —
run ingestion as an admin (see `docs/DEVELOPMENT.md` §6) to fill
it.

## Tests

```bash
cd backend
.venv/bin/python -m pytest tests -q   # 197 tests passing
```

```bash
cd frontend
npm run build                     # production build check, 14 pages
npm run lint                      # ESLint, clean
```

Per-file coverage, the E2E smoke walk (23/23) and the known
flaky-test history: `docs/TESTING.md`. Final verification record:
`docs/TESTING_REPORT.md`.

## Environment configuration

Copy `.env.example` to `.env`. Never commit a real `.env`. No secrets
are stored in this repository. AI provider keys come only from
environment variables. Full variable list with defaults and which
phase needs each: `docs/DEVELOPMENT.md` §4.

## Data-source attribution

- NVD — National Vulnerability Database (NIST), CVE API 2.0
- CISA — Known Exploited Vulnerabilities catalog
- FIRST — Exploit Prediction Scoring System (EPSS)
- MITRE — ATT&CK (enterprise) and CWE

All data is public. Original reference links are preserved on every
vulnerability record.

## Documentation

- `docs/ARCHITECTURE.md` — system design, diagrams, AI design
- `docs/DATABASE.md` — full schema (21 tables)
- `docs/ROADMAP.md` — 10-phase plan, all phases done
- `docs/API.md` — complete REST reference (all 50 routes)
- `docs/AI_PIPELINE.md` — provider adapters, embeddings, RAG,
  analyst, assistant, fallback
- `docs/SECURITY.md` — Phase 9 security review (checklist,
  fixes, residual risks)
- `docs/TESTING.md` — how to run tests, coverage, E2E walk
- `docs/DEVELOPMENT.md` — setup, env vars, troubleshooting
- `docs/TESTING_REPORT.md` — final testing report

## Security

Full review in `docs/SECURITY.md` (Phase 9): 21 checklist items,
4 fixes made in-phase (real DB health check, login rate limit,
common-password denylist, CSRF Origin check), 8 residual risks
documented. Practice is lab-only: this platform reads public
intelligence and never launches scans or attacks against any
system.

## Limitations — read before deploying

- **Docker Compose unverified here.** Never run in the build VM
  (no Docker). First run must be on the developer machine.
- **No real-browser click-test** of the login / register /
  AI-assistant pages. They build clean; nobody has clicked
  through them in a browser yet.
- **AI provider mode untested without keys.** All provider tests
  use mocked transports. The non-AI fallback is the only mode
  verified end-to-end.
- **Investigation status is tracked via status-tagged notes,
  not a DB column.** `GET /research/collections/{id}/status`
  reads the latest note tagged `"status"`; with none, the status
  is `"not_started"`. See `docs/API.md` §11.
- **SQLite is the dev default; Postgres + pgvector is for
  production.** The suite runs on SQLite. Vector search,
  `tsvector` and concurrent ingestion are unverified here, and
  the **pgvector HNSW index is not yet created**.
- **`/docs`, `/redoc` and `/openapi.json` are public** by design
  in this codebase — gate them before any public deployment
  (see `docs/SECURITY.md` R4).
- **Login rate limit is in-memory and per-process** — it does
  not survive a restart and is not shared across workers
  (see `docs/SECURITY.md` R1).

## License

To be decided by the project owner.
