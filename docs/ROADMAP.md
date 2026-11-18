# CyberMap AI — Implementation Roadmap

10 phases, worked in order. A phase is only marked done when its tests
pass and the app still starts.

| Phase | Scope | Status |
|---|---|---|
| 1 | Repository analysis & planning — architecture, DB schema, roadmap, env vars | ✅ Done |
| 2 | Foundation — monorepo, Docker Compose, env config, frontend↔backend health check | ✅ Done |
| 3 | Database & authentication — models, Alembic, Argon2 auth, roles, data isolation | ✅ Done — 46 pytest tests pass (incl. migration upgrade→downgrade→upgrade cycle on temp SQLite, auth flows, isolation); uvicorn serves /docs 200 |
| 4 | Intelligence ingestion — NVD, CISA KEV, EPSS, MITRE ATT&CK/CWE connectors | ✅ Done (live: 50 CVEs, 984 CWE, 706 techniques, 1782 KEV, 48 EPSS; 123 tests) |
| 5 | Core platform — dashboard, vulnerability explorer, detail pages, threat intel center | ✅ Done (21 tests; live smoke: 50 CVEs, dashboard + detail + EPSS ranking verified; 179 tests) |
| 6 | AI system — provider adapters, embeddings, pgvector RAG, analyst, assistant, citations, fallback | ✅ Done (46 AI tests; fallback fully working; 123 tests total) |
| 7 | Knowledge graph — graph API + React Flow UI | ✅ Done (13 tests; live graph verified; 178 tests) |
| 8 | Research & learning — collections, bookmarks, notes, saved analyses, learning center | ✅ Done (21 tests; isolation verified live; 9 learning topics; 178 tests) |
| 9 | Security & QA — tests, static analysis, dependency checks, authz tests, security review | ✅ Done (18 new tests; 197 total, 3 consecutive full runs green; 23/23 E2E walk; 4 fixes — see docs/SECURITY.md) |
| 10 | Final delivery — README, docs, GitHub, testing report | ✅ Done (docs/API.md, TESTING.md, DEVELOPMENT.md, TESTING_REPORT.md written; README + ROADMAP + ARCHITECTURE + DATABASE updated; push manifest generated — see docs/TESTING_REPORT.md) |

## Phase 1 — done

- `docs/ARCHITECTURE.md` — stack, diagrams, module map, AI design,
  security principles.
- `docs/DATABASE.md` — full schema for all 21 tables.
- This roadmap.

## Phase 2 — done

- Monorepo: `frontend/` (Next.js 16, TypeScript, Tailwind 4, TanStack
  Query, Zod) + `backend/` (FastAPI, Pydantic, SQLAlchemy).
- `docker-compose.yml`: Postgres 16 + pgvector, Redis, backend, frontend.
- `.env.example` (placeholders only), `.gitignore`.
- Backend health endpoints `GET /health` and `GET /api/v1/health`
  (4 pytest tests passing), root endpoint, `/docs` Swagger UI.
- Frontend home page calls the backend health endpoint live and shows
  the result; honest "no data ingested yet" empty state — no fabricated
  statistics.

Verified in the build workspace: pytest 4 passed; uvicorn serves
`/`, `/health`, `/api/v1/health`, `/docs` (200). Docker Compose was
**not** run here (no Docker in this environment) — it must be verified
on the developer machine.

## Phase 3 — done

- SQLAlchemy models for all 21 tables in `docs/DATABASE.md`
  (`backend/app/models/`), dialect-aware embedding column
  (`vector(1536)` on Postgres, JSON on SQLite).
- Alembic initial migration `0001` (`backend/migrations/`): creates
  all tables, creates the pgvector extension only on Postgres, seeds
  the 3 roles + 5 data_sources rows. Verified on a fresh SQLite file:
  upgrade head → downgrade base → upgrade head again.
- Auth (`/api/v1/auth`): register (always role `user`), login,
  logout, `/me`, password change (revokes other sessions), Argon2id
  hashing, HTTP-only session cookies storing only a SHA-256 hash in
  the DB, `require_role("admin")` guard, audit logging for
  `auth.register/login/logout/login_failed`.
- Tests: 46 pytest tests pass (4 health + 15 auth + 7 isolation +
  1 migration + 19 models), all on fresh temp SQLite DBs.
- Docker Compose and PostgreSQL/pgvector were **not** verified here
  (no Docker/Postgres in this environment) — verify on the developer
  machine before Phase 4 ingestion runs against Postgres.

## Phase 4 — done

- Connectors: NVD CVE API 2.0, CISA KEV JSON feed, FIRST EPSS API,
  MITRE ATT&CK STIX (enterprise-attack.json), MITRE CWE XML.
- Validation, normalization, dedup, safe upserts, retry + exponential
  backoff, rate-limit respect, `ingestion_jobs` logging, sync-status
  endpoint. Manual admin sync. Ingestion health view.

## Phase 5 — done

- Dashboard: real DB stats only, date-range filter, charts (Recharts),
  last sync timestamp, click-through to filtered records.
- Explorer: CVE ID / text search, severity / date / CWE / CVSS / EPSS /
  vendor / KEV filters, sorting, pagination.
- Detail page: all fields from `docs/DATABASE.md` §2.4, references,
  related CVEs, remediation, AI explanation slot.
- Threat intelligence center: KEV additions, EPSS ranking, timeline,
  CVSS vs EPSS vs KEV explainer.

## Phase 6 — done

- Adapters: OpenAI / Groq / Google Gemini (env-configured, no keys in
  code) + local embedding fallback.
- Embeddings + pgvector RAG; grounded prompts; structured 10-section
  analysis; citations on every AI answer.
- Research assistant chat: history, streaming where supported, rate
  limits, saved answers.
- Non-AI fallback fully working when no provider is configured.

## Phase 7 — done

- Graph API: nodes/edges from `vulnerability_relationships`, expansion,
  pagination, source vs inferred marking.
- React Flow UI: zoom/pan, node details, type filters, search,
  navigation to CVE pages.

## Phase 8 — done

- Collections, bookmarks, notes, saved analyses, comparison lists,
  export — all user-isolated.
- Learning center: OWASP Top 10, CWE categories, secure coding,
  knowledge checks — clearly separated from real vulnerability records.

## Phase 9 — done

- Full test runs (pytest + frontend build/lint + 23-step live E2E
  smoke walk, 23/23 as expected).
- Security review of the actual implementation
  (`docs/SECURITY.md` — 21 checklist items, 4 fixes made in-phase:
  real DB health check, login rate limit, common-password
  denylist, CSRF Origin check; 8 residual risks documented).
- Backend suite: 197 tests, 3 consecutive full runs green.
  Frontend: `npm run build` 14 pages, `npm run lint` clean.
  Login, register and AI-assistant pages added (were missing).

## Phase 10 — done

- Complete README + `docs/API.md` (all 50 routes, verified against
  the live app), `docs/TESTING.md`, `docs/DEVELOPMENT.md`,
  `docs/TESTING_REPORT.md`; `docs/ROADMAP.md`,
  `docs/ARCHITECTURE.md` and `docs/DATABASE.md` updated to done.
- Push manifest generated at
  `~/workspace/cybermap-ai-push-manifest.txt` (outside the repo
  tree); secret scan clean; per-phase commit messages listed in
  `docs/TESTING_REPORT.md` §7.
- GitHub push itself was **not** done by this phase (coordinator /
  morning push): target repo `sahilm4711-cyber/CYBERMAP.AI`
  (public, empty, main) — the name is CYBERMAP.AI, not
  CyberMap-AI.
- Honest gaps carried forward: Docker Compose unverified,
  no real-browser click-test, provider-mode AI untested without
  keys, Postgres/pgvector migration unverified, HNSW index not
  yet created. See `docs/TESTING_REPORT.md` §6.
