# CyberMap AI — Development Guide

> **Status:** Phase 10. How to set up, run, and debug CyberMap AI
> locally. The honest headline: the non-Docker setup below is the
> one that was actually used to build and verify every phase in
> this workspace. **Docker Compose was never run here** (no Docker
> in the build VM) — the file is written and reviewed, but it must
> be run for the first time on the developer machine (see §3).

## 1. Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Node.js + npm | 20+ | Verified with Node v24.22.1 in this VM |
| Python | 3.12+ | Verified with Python 3.12.3 |
| Docker + Docker Compose | any recent | **Only for the full stack (§3). Not available in the build VM.** |
| Git | any recent | For the push workflow |

No locally hosted LLM is required. AI runs through external
provider adapters, and the platform works fully without any
provider configured (non-AI fallback mode).

**Developer machine:** ASUS TUF F16, NVIDIA RTX 3050. (The RTX
4050 / 16 GB figure that appeared in an early project prompt was
wrong — the machine is the RTX 3050 model. Never write RTX 4050
in docs, configs or commit messages for this project.)

## 2. Local setup without Docker (the verified path)

This is the setup every phase was built and tested with.

```bash
# 0. Clone the repo (after the morning push) and enter it
git clone https://github.com/sahilm4711-cyber/CYBERMAP.AI.git
cd CYBERMAP.AI

# 1. Backend — virtualenv + dependencies
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt   # runtime deps + pytest

# 2. Environment — copy the template and fill in your own values
cp ../.env.example ../.env
# Edit ../.env: at minimum set SECRET_KEY and POSTGRES_PASSWORD
# to long random strings. Leave AI_PROVIDER empty for fallback mode.

# 3. Database — create all 21 tables (SQLite file by default)
.venv/bin/alembic upgrade head
# Creates backend/cybermap.db on first run (SQLite default).
# See §5 for the Postgres path.

# 4. Run the backend
.venv/bin/python -m uvicorn app.main:app --reload --port 8000
# API + Swagger docs: http://localhost:8000/docs
# Health:               http://localhost:8000/health

# 5. Frontend (new terminal)
cd ../frontend
npm install
npm run dev            # http://localhost:3000
```

### First run checklist

1. `curl http://localhost:8000/health` → `{"status":"ok", ...,
   "database":"ok","ai_mode":"fallback"}`.
2. Open http://localhost:3000 — the home page shows the live
   backend health check.
3. Register an account (`/register`), log in, open the dashboard.
   With a fresh DB the dashboard is honestly empty — no data has
   been ingested yet. That is by design, not a bug.
4. Ingest data (needs an **admin** account — see §6):
   `POST /api/v1/ingestion/sync/nvd` (or use the admin flow in
   §6), then re-check the dashboard.

### Useful commands

```bash
# Backend tests (197 tests, ~75 s)
cd backend && .venv/bin/python -m pytest tests -q

# Frontend checks
cd frontend && npm run build && npm run lint

# Apply / inspect migrations
cd backend
.venv/bin/alembic upgrade head
.venv/bin/alembic current
.venv/bin/alembic history

# Fresh database (dev only — deletes all local data)
rm backend/cybermap.db
cd backend && .venv/bin/alembic upgrade head
```

## 3. Docker Compose (full stack) — NOT verified in the build VM

```bash
cp .env.example .env   # fill in your own values first
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API + docs: http://localhost:8000/docs
- Postgres 16 + pgvector on `:5432`, Redis 7 on `:6379`.

> ⚠️ **Honest note:** this file (`docker-compose.yml`) was written
> and reviewed but **never run** — there is no Docker in the build
> VM where Phases 1–10 were developed. The first real run must
> happen on the developer machine. If it fails, the likely
> suspects are: the `pgvector/pgvector:pg16` image not pulling,
> the backend Dockerfile path (`infrastructure/docker/
> backend.Dockerfile`), or the `./backend:/code` volume mount
> colliding with the container's installed packages. Fix it there
> and record what changed — do not assume it works because the
> file looks right.

What Compose gives you that the local setup does not:

- **PostgreSQL 16 + pgvector** instead of SQLite — required for
  real vector search (the HNSW index) and the supported
  production path.
- **Redis** for caching / job coordination (the app also runs
  with Redis disabled — `REDIS_URL` empty — but the login rate
  limiter is in-memory per process, see `docs/SECURITY.md` R1).

## 4. Environment variables — full list

Copy `.env.example` to `.env`. **Never commit a real `.env`.**
Defaults are the values in `backend/app/core/config.py` (and the
Compose defaults) when the variable is unset.

| Variable | Default | Phase | Notes |
|---|---|---|---|
| `ENVIRONMENT` | `development` | 2 | `development` \| `staging` \| `production`. Returned by `/health`. |
| `SECRET_KEY` | `change-me-to-a-long-random-string` | 3 | **Must be replaced** with a long random string. The session-cookie secret is derived from it. |
| `DEBUG` | `false` | 2 | FastAPI debug. Keep `false` — `true` leaks tracebacks. |
| `DATABASE_URL` | `sqlite:///./cybermap.db` | 3 | Postgres in Docker: `postgresql+psycopg2://cybermap:<password>@localhost:5432/cybermap`. SQLite is the dev default; Postgres + pgvector is the production path. |
| `POSTGRES_USER` | `cybermap` | 2 | Compose / Postgres user. |
| `POSTGRES_PASSWORD` | `change-me-in-.env` | 2 | **Must be replaced** in a real `.env`. |
| `POSTGRES_DB` | `cybermap` | 2 | Compose / Postgres database name. |
| `POSTGRES_PORT` | `5432` | 2 | Host port Compose maps Postgres to. |
| `REDIS_URL` | *(empty — Redis disabled)* | 2 | e.g. `redis://localhost:6379/0`. Empty = the app runs without Redis. |
| `REDIS_PORT` | `6379` | 2 | Host port Compose maps Redis to. |
| `CORS_ORIGINS` | `http://localhost:3000` | 2 | Comma-separated allow-list. Never `*` — the Phase 9 CSRF check trusts this list. |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | 2 | Frontend → backend base URL (baked into the frontend at build time). |
| `SESSION_COOKIE_NAME` | `cybermap_session` | 3 | Cookie name for the session token. |
| `SESSION_EXPIRE_DAYS` | `7` | 3 | Session lifetime in days. |
| `SESSION_COOKIE_SECURE` | `false` | 3 | **Set `true` in production** (HTTPS only). `false` is for local `http://` development. |
| `SESSION_COOKIE_SAMESITE` | `lax` | 3 | `lax` is the default; the CSRF check is the second layer. |
| `PASSWORD_MIN_LENGTH` | `8` | 3 | Minimum password length (enforced in Pydantic + service; floor is 8). |
| `AI_PROVIDER` | *(empty — fallback mode)* | 6 | `openai` \| `groq` \| `google-gemini` (also `gemini`, `google`). Empty = fully functional non-AI fallback. |
| `AI_MODEL` | *(empty — provider default)* | 6 | e.g. `gpt-4o-mini`. Optional; the provider default is used otherwise. |
| `OPENAI_API_KEY` | *(empty)* | 6 | Only the key for the chosen provider. Read at call time, never logged, never committed. |
| `GROQ_API_KEY` | *(empty)* | 6 | Same. Note: Groq offers no embeddings API — `embed()` raises `NotImplementedError`. |
| `GOOGLE_API_KEY` | *(empty)* | 6 | Same (Gemini). |
| `NVD_API_KEY` | *(empty)* | 4 | Optional free NVD API key — raises the NVD rate limit. Without it the connector works anonymously at the lower public rate. |

Variables **not** in `.env.example` but read by the code: `DEBUG`
(see above) and `REDIS_URL` (empty default in `config.py`).
Everything else the app reads comes from this table.

## 5. Database: SQLite (dev) vs Postgres (production)

- **SQLite (default, no Docker):** `DATABASE_URL` unset →
  `sqlite:///./cybermap.db`. Embeddings fall back to a JSON
  column; similarity is computed in Python (cosine). Correct,
  but slower — and the **HNSW index is not created** on SQLite.
  Fine for development and for the 50-CVE dev dataset.
- **Postgres + pgvector (Docker / production):** set
  `DATABASE_URL=postgresql+psycopg2://...`. The Alembic
  migration creates the `vector` extension (Postgres only) and
  the `embeddings.embedding` column is a real `vector(1536)`.
  The HNSW index (`vector_cosine_ops`) is declared in the
  design (`docs/DATABASE.md` §2.20) but **not yet created** —
  that is a known gap (see `docs/TESTING_REPORT.md` §6). Run
  the migration, then verify the extension and the column type
  with `psql \d embeddings` before trusting vector search.
- **Migrations:** every schema change gets its own Alembic
  migration; never `ALTER TABLE` by hand. The initial migration
  is `backend/migrations/versions/0001_initial.py` (all 21
  tables + role and data-source seeds). Verified upgrade →
  downgrade → upgrade on SQLite (`test_migrations.py`).

## 6. Making an admin account (for ingestion)

Registration always creates role `user` — there is no
sign-up-to-admin path, by design. To run ingestion
(`POST /api/v1/ingestion/sync/{source}` is admin-only):

```bash
# SQLite dev DB — set the role directly:
cd backend
.venv/bin/python -c "
import sqlite3
db = sqlite3.connect('cybermap.db')
db.execute(\"UPDATE users SET role_id = (SELECT id FROM roles WHERE name='admin') WHERE username='professor'\")
db.commit()
"
# Then log out and log back in so the new role takes effect.
```

On Postgres the same `UPDATE` applies (via `psql`). A proper
admin-management endpoint is a post-Phase-10 task.

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Address already in use` on `:8000` / `:3000` | Another uvicorn / Next dev server is running | Find it (`lsof -i :8000`, `ps aux \| grep uvicorn`) and stop it, or use another port: `uvicorn app.main:app --port 8001` / `npm run dev -- -p 3001` (and update `NEXT_PUBLIC_API_URL` / `CORS_ORIGINS` to match) |
| `database is locked` (SQLite) | Two writers at once — e.g. tests running while the dev server writes, or two uvicorn workers | Stop one of them. SQLite allows a single writer; for concurrent ingestion use Postgres. Never delete `cybermap.db` while the server is running. |
| `GET /health` shows `"database": "error"` | The DB file / Postgres is unreachable (wrong `DATABASE_URL`, Postgres down, permissions) | Check `DATABASE_URL`, check the file exists (`ls -la backend/cybermap.db`), re-run `alembic upgrade head`. The service still reports `status: "ok"` — the process is up, the store is not. |
| NVD sync returns 429 / very slow | NVD public rate limit (anonymous) or the 5-minute per-source guard | Set `NVD_API_KEY` in `.env` (free, raises the limit). The 5-minute guard is intentional: wait, then retry. Do **not** hammer the endpoint — ingestion respects rate limits and retries with exponential backoff. |
| `401` on every API call from the frontend | Session cookie not sent | The frontend must call the backend on the same origin setup the cookie was set for (`NEXT_PUBLIC_API_URL` must match the backend you logged into; cookies are `SameSite=Lax`, so cross-site `fetch` will not carry them). Check the browser's cookie storage for `cybermap_session`. |
| `403` on a `POST` from the browser | CSRF Origin check (Phase 9) | The `Origin` header must be in `CORS_ORIGINS`. If you serve the frontend from a new origin, add it to `CORS_ORIGINS` in `.env` and restart the backend. |
| `422` on register | Password too short / common, or username < 3 chars | Password ≥ 8 chars, not on the common-password denylist, not equal to the username. See `docs/API.md` §4. |
| AI answers say "rule-based summary — no AI provider configured" | No provider set — this is **expected** | Set `AI_PROVIDER` + the matching `*_API_KEY` in `.env` and restart. Verify with `GET /api/v1/ai/status` → `mode: "provider"`. |
| "No model downloaded" / embedding errors | **There is no model to download in this codebase.** The local embedding fallback is a deterministic hashing embedding (`local-hash-384`, see `docs/AI_PIPELINE.md` §2) — it needs no download and no GPU. If a sentence-transformer path is added later, *that* is when model-download troubleshooting applies; today it does not. |
| `npm run build` fails with a type error | Stale `.next` cache or a `node_modules` mismatch | `rm -rf frontend/.next frontend/node_modules && cd frontend && npm install && npm run build` |
| `alembic upgrade head` fails on a fresh clone | `.env` missing or `DATABASE_URL` pointing at a Postgres that is not running | Copy `.env.example` → `.env` first; for the SQLite default, unset `DATABASE_URL` or leave the example value. |
| Frontend shows "no data ingested yet" | Fresh DB, no ingestion run yet | Expected. Log in as admin (§6) and run `POST /api/v1/ingestion/sync/nvd` (then `kev`, `epss`, `mitre`). |

## 8. Project layout (for new contributors)

```
cybermap-ai/
├── frontend/          # Next.js 16 App Router + TypeScript + Tailwind 4
│   ├── app/           # Pages: dashboard, vulnerabilities, intelligence,
│   │                  # attack-graph, ai-assistant, research, learning,
│   │                  # login, register
│   ├── components/ hooks/ lib/ services/ types/
├── backend/           # FastAPI + SQLAlchemy 2 + Alembic
│   ├── app/
│   │   ├── main.py         # create_app(), CORS, router registration
│   │   ├── api/v1/         # Routers (one file per domain)
│   │   ├── core/           # config (env), database engine
│   │   ├── models/         # SQLAlchemy models (21 tables)
│   │   ├── schemas/        # Pydantic request/response schemas
│   │   ├── services/       # Business logic (one service per domain)
│   │   ├── repositories/   # Data access
│   │   ├── integrations/   # NVD / KEV / EPSS / MITRE clients
│   │   ├── ingestion/      # Connectors + orchestration + sync logging
│   │   ├── ai/             # Provider adapters, embeddings, RAG, prompts
│   │   ├── security/       # Password hashing, sessions, RBAC, rate limiting, CSRF
│   │   └── workers/        # Background jobs (ingestion scheduler)
│   ├── migrations/         # Alembic (0001_initial)
│   ├── scripts/            # generate_learning_topics.py
│   └── tests/              # pytest — 197 tests
├── infrastructure/docker/  # backend.Dockerfile, frontend.Dockerfile
├── docs/                   # ARCHITECTURE, DATABASE, ROADMAP, API,
│                           # AI_PIPELINE, SECURITY, TESTING,
│                           # DEVELOPMENT, TESTING_REPORT
├── docker-compose.yml      # Full stack — NOT verified in the build VM (§3)
├── .env.example
└── README.md
```

## 9. Rules for contributors (carried from the build)

1. **Lab-only / public data only.** This platform reads public
   intelligence and never launches scans or attacks against any
   system.
2. **No secrets in code, ever.** Keys come from env vars only.
   Run the secret scan in `docs/TESTING.md` §6 before pushing.
3. **Every statistic comes from the database.** Missing data is
   shown as "unavailable", never as zero risk, never fabricated.
4. **Owner-only 404s.** Another user's private object returns
   404, never 403 — do not "fix" this to 403.
5. **AI never invents CVE facts.** Every number comes from the
   database and is cited; retrieved content is untrusted data,
   never instructions.
6. **Tests before push.** Full backend suite + `npm run build` +
   `npm run lint` must all pass. If a test fails once and then
   passes, record it (see `docs/TESTING.md` §4) — do not silently
   re-run until green.
7. **Docker Compose is unverified until someone runs it.**
   The first successful `docker compose up` on a real machine
   should update this document and `docs/TESTING_REPORT.md`.
