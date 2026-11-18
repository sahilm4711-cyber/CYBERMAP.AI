# CyberMap AI — Deployment Guide (Vercel + Render)

> **Status:** configs prepared 2026-11-18, rewired 2026-11-18 for a
> free Supabase database. **Not yet deployed.** This guide is the
> deploy runbook for the setup the project owner chose: frontend on
> Vercel, backend on Render, Postgres on Supabase (free tier) — the
> same split as Curion, except the database is Supabase free instead
> of Render's paid Postgres. The three deploy files are `vercel.json`,
> `render.yaml` (both at the repo root) and this guide.
>
> ⚠️ **Do not skip §1.** Two real bugs were found while preparing
> these configs; the workarounds are baked into `render.yaml`, and
> §1.9 (Supabase setup) must be done before the first Render deploy.
> The pre-deploy code changes are already applied (§1.1, §1.3).

## Architecture

```
User's browser
    │  https://<your-app>.vercel.app
    ▼
Vercel — Next.js 16 frontend (static + SSR)
    │  fetch(..., credentials: "include")
    │  NEXT_PUBLIC_API_URL = https://cybermap-ai-backend.onrender.com
    ▼
Render — FastAPI backend (uvicorn, 1 instance)
    │  DATABASE_URL (Supabase direct connection, port 5432)
    ▼
Supabase — managed PostgreSQL + pgvector (free tier, 500 MB)
```

The frontend and backend are on **different sites** (`vercel.app`
vs `onrender.com`). That one fact drives the two most important
settings in this guide: the session cookie must be
`SameSite=None; Secure` (§1.4) and `CORS_ORIGINS` must list the exact
Vercel URL (§1.5). Get either wrong and login silently breaks.

## 1. Pre-deploy blockers — read before touching any dashboard

### 1.1 Postgres driver — RESOLVED (was missing from `requirements.txt`)

`backend/requirements.txt` used to contain **no Postgres driver**
(`psycopg2` / `psycopg`) — verified locally in the project venv,
every URL form failed with `ModuleNotFoundError`, so the backend
could not connect to Postgres as written. **Fixed 2026-11-18:**
`psycopg[binary]==3.2.10` was added to `backend/requirements.txt`
and the full backend test suite still passes (197 tests, 0 failed).
No action needed — `render.yaml` installs the driver from
`requirements.txt` at build time.

### 1.2 Render's `DATABASE_URL` scheme is rejected by SQLAlchemy 2.0 (verified)

Supabase issues connection strings as `postgres://user:pass@host:5432/db`
(direct connection; see §1.9).
SQLAlchemy 2.0 removed the `postgres://` alias — verified locally:

- `postgres://…` → `NoSuchModuleError: Can't load plugin: sqlalchemy.dialects:postgres`

Workaround already in `render.yaml`: the start command rewrites a
leading `postgres://` to `postgresql+psycopg://` before launching
uvicorn (a no-op if the URL already has the right scheme).
**Durable fix (optional):** normalize the scheme in
`backend/app/core/config.py` when `database_url` is loaded, e.g.
`if url.startswith("postgres://"): url = "postgresql+psycopg://" + url[len("postgres://"):]`.

### 1.3 `/docs`, `/redoc`, `/openapi.json` — RESOLVED (was public)

`backend/app/main.py` used to set `docs_url="/docs"` unconditionally;
no environment flag gated it. This was residual risk R4 in
`docs/SECURITY.md`. **Fixed 2026-11-18 (commit 55d3cdb):** the docs
are now environment-gated — `docs_url`, `redoc_url` and `openapi_url`
are all `None` when `ENVIRONMENT=production` (verified: `GET /docs`
→ 404 in production mode, still available in local development).
No action needed — `render.yaml` already sets
`ENVIRONMENT=production`. Verify live with
`curl -s -o /dev/null -w "%{http_code}" https://<backend>/docs`
— expect **404**.

### 1.4 Cross-site session cookie (why login would silently fail)

The frontend sends `credentials: "include"` on every API call
(`frontend/lib/services/client.ts`, `auth.ts`, …). The cookie's
default is `SameSite=Lax`, and a Lax cookie is **not** sent on a
cross-site `fetch` — so with the defaults, login would return 200
and then every later request would act logged-out. `render.yaml`
already sets the fix:

- `SESSION_COOKIE_SAMESITE=none`
- `SESSION_COOKIE_SECURE=true` (required with `None`; Render serves HTTPS)

Do not change these back to `lax`/`false` on the live deployment.

### 1.5 `CORS_ORIGINS` must be the exact Vercel URL

The CSRF check (`backend/app/security/csrf.py`) rejects any
POST/PUT/PATCH/DELETE whose `Origin` header is not in the CORS
allow-list — that includes **login and register**. So while
`CORS_ORIGINS` still holds the placeholder
`https://YOUR-VERCEL-APP.vercel.app`, login returns **403**.
Set it to the real Vercel origin (no trailing slash) in Step 5.

### 1.6 One backend instance only

The login rate limit is in-memory and per-process (R1). A second
instance would give every attacker a second, separate 10-guesses
budget and would not share counters. Keep `numInstances` at the
default (1). Do not scale the web service horizontally until the
rate limit moves to Redis.

### 1.7 Redis is deliberately NOT provisioned

`render.yaml` has no Redis/Key Value service. That is intentional:
the code never uses Redis — no client library in
`requirements.txt`, no import anywhere. The login rate limit is
in-memory, ingestion state lives in the `ingestion_jobs` table.
Do not pay for a service nothing reads. Add one only when a future
phase actually uses it (and then wire `REDIS_URL`).

### 1.8 Cost — $0 total

| Piece | Plan in these configs | Approx. cost |
|---|---|---|
| Render web service | `free` (spins down after ~15 min idle; first request after sleep is slow) | $0 |
| Supabase Postgres | Free tier (500 MB database, pgvector included; pauses after 1 week idle — §1.9) | $0 |
| Vercel frontend | Hobby | $0 |
| **Total** | | **$0** |

Switch the web service to `plan: starter` in `render.yaml` (or in
the dashboard, ~$7/month) if cold starts are unacceptable.

### 1.9 Supabase database (free tier) — do this first

The database lives on Supabase, not on Render. `render.yaml` has no
`databases:` section; the backend reads the connection string from
the `DATABASE_URL` environment variable, which you set by hand in
the Render dashboard (it is `sync: false` in `render.yaml`).

1. **Create the project.** Supabase dashboard → **New project** →
   pick the Free plan ($0 — 500 MB database, 2 free projects, no
   credit card). The owner already has a Supabase account from
   Curion, so use that account.
2. **Copy the DIRECT connection string.** Project Settings →
   **Database** → **Connection string** → **URI**. Use the direct
   connection (`db.<ref>.supabase.co`, **port 5432**) — NOT the
   pooler (`pooler.supabase.com`, port 6543). The pooler runs in
   PgBouncer transaction mode, which can break SQLAlchemy/psycopg
   prepared statements; the direct connection avoids that entirely.
   The URI looks like
   `postgres://postgres:<password>@db.<ref>.supabase.co:5432/postgres`
   (Supabase shows it with the `postgres://` scheme; the
   startCommand rewrite in `render.yaml` handles that — see §1.2).
3. **Paste it into Render.** Render dashboard → `cybermap-ai-backend`
   → **Environment** → set `DATABASE_URL` to that URI. Do this
   **before the first successful build** — the build runs Alembic,
   and the migration fails if the database is unreachable (see
   Step 2).
4. **SSL.** Supabase requires SSL. psycopg3 negotiates SSL by
   default (`sslmode=prefer`), so the plain URI usually connects
   fine. If the first deploy fails to connect, append
   `?sslmode=require` to the URI in the Render dashboard and
   redeploy.
5. **Vector extension.** Migration `0001_initial` already runs
   `CREATE EXTENSION IF NOT EXISTS vector` (Postgres only — it is
   guarded by a dialect check), and Supabase supports the `vector`
   extension. No manual step should be needed. If the migration
   fails on the extension, run `CREATE EXTENSION vector;` once in
   the Supabase **SQL Editor** and redeploy.
6. **Pause rule.** Free-tier projects pause after **1 week of
   inactivity** and are resumed from the Supabase dashboard. The
   first visit after a pause fails (backend reports
   `database: "error"` on `/health`) until the project is resumed.
   Resume it before demoing the site if it has been idle.

## 2. Environment variables

### Render — backend (`cybermap-ai-backend`)

Set by `render.yaml` on Blueprint apply, except the `sync: false`
rows, which you set in the dashboard (leave empty for fallback mode).

| Variable | Value | Notes |
|---|---|---|
| `ENVIRONMENT` | `production` | Drives the §1.3 docs gate (applied — `/docs` is 404 in production) |
| `SECRET_KEY` | *(generated by Render)* | Session signing. Never commit a value |
| `DATABASE_URL` | *(set in dashboard — Supabase direct connection string, §1.9)* | Scheme rewritten at start (§1.2); `sync: false` in render.yaml |
| `CORS_ORIGINS` | `https://YOUR-VERCEL-APP.vercel.app` → **replace with the real Vercel URL in Step 5** | Exact origin, no trailing slash (§1.5) |
| `SESSION_COOKIE_SECURE` | `true` | §1.4 |
| `SESSION_COOKIE_SAMESITE` | `none` | §1.4 |
| `AI_PROVIDER` / `AI_MODEL` | *(empty)* | Empty = non-AI fallback (verified) |
| `NVD_API_KEY` | *(dashboard, optional)* | Free key; raises the NVD rate limit |
| `OPENAI_API_KEY` / `GROQ_API_KEY` / `GOOGLE_API_KEY` | *(dashboard, optional)* | Only one provider is ever needed; never commit keys |

### Vercel — frontend

| Variable | Value | Notes |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `https://cybermap-ai-backend.onrender.com` | **Set in the Vercel dashboard BEFORE the first deploy.** `NEXT_PUBLIC_*` values are baked into the JavaScript at build time — changing the value later requires a redeploy. The placeholder in `vercel.json` must be replaced. |

## 3. Deploy steps (in order — backend first)

### Step 0 — Push these files

```bash
git add vercel.json render.yaml docs/DEPLOYMENT.md
git commit -m "Add Vercel + Render deployment configs"
git push origin main
```

(The §1.3 docs-gating change is already applied and pushed.)

### Step 1 — Supabase: create the project (do this first)

Follow §1.9: create the free project, copy the DIRECT connection
string (port 5432, not the pooler). Keep it ready for Step 2.

### Step 2 — Render: create the Blueprint

1. Render dashboard → **New → Blueprint** → select the
   `sahilm4711-cyber/CYBERMAP.AI` repo.
2. Render shows one resource from `render.yaml`:
   `cybermap-ai-backend` (web service). There is no Render
   database — the database lives on Supabase (§1.9). Apply.
3. **Set `DATABASE_URL` now**, in the service's **Environment**
   tab, to the Supabase direct connection string from Step 1. The
   first build runs Alembic, and it fails if the database is
   unreachable — if the build already failed, set the variable and
   use **Manual Deploy → Deploy latest commit** to rebuild.
4. Watch the build log. It must show `pip install` succeeding
   and then Alembic running migration `0001_initial` — that
   migration runs `CREATE EXTENSION IF NOT EXISTS vector`
   (Supabase supports the `vector` extension; see §1.9 step 5 if
   it fails).

### Step 3 — Verify the backend

```bash
BACKEND=https://cybermap-ai-backend.onrender.com
curl -s $BACKEND/health
# expect: {"status":"ok", ... "database":"ok", "ai_mode":"fallback", ...}
curl -s $BACKEND/
# expect: {"service":"cybermap-ai", "version":"0.1.0", ...}
curl -s -o /dev/null -w "%{http_code}\n" $BACKEND/docs
# expect: 404 (§1.3 is already applied)
```

`database: "error"` here means the backend is up but cannot reach
Postgres — check the logs for the driver/scheme issues in §1.1–1.2.
On the free web-service plan the first request after idle takes
~30–60 s (cold start); that is normal, not an error.

### Step 4 — Vercel: deploy the frontend

1. Vercel dashboard → **Add New → Project** → import
   `sahilm4711-cyber/CYBERMAP.AI`.
2. **Before the first deploy**, add the environment variable
   `NEXT_PUBLIC_API_URL=https://cybermap-ai-backend.onrender.com`
   (Production). The placeholder in `vercel.json` is only a fallback.
3. Deploy with the defaults — `vercel.json` already points the
   install/build at `frontend/` (no Root Directory change needed).
   If you prefer the dashboard route instead, set **Root Directory**
   to `frontend` and delete the `--prefix frontend` parts from
   `vercel.json`.
4. Open the Vercel URL. The home page should load and the dashboard
   should show the "no intelligence data yet" empty state (the live
   database starts empty — that is expected, not a bug).

### Step 5 — Point the backend at the real frontend URL

1. In Render, open `cybermap-ai-backend` → **Environment** → set
   `CORS_ORIGINS` to the exact Vercel origin, e.g.
   `https://cybermap-ai.vercel.app` (no trailing slash).
2. Save — Render redeploys the service automatically.
3. End-to-end check in a real browser: register → log in →
   dashboard loads → open a CVE → add it to a collection →
   log out → `/me` asks for login again. If login returns 403,
   `CORS_ORIGINS` is wrong (§1.5). If login succeeds but the next
   page acts logged-out, the cookie settings are wrong (§1.4).

### Step 6 — Fill the database (admin ingestion)

Registration always creates role `user`; ingestion endpoints are
admin-only. Promote the first user, then sync each source once
(development guide `docs/DEVELOPMENT.md` §6 has the same steps for
local use):

```bash
# 1. In Supabase, open the SQL Editor:
UPDATE users SET role_id = (SELECT id FROM roles WHERE name='admin')
WHERE username = '<your-username>';
# 2. Log out and log back in so the new role takes effect.
# 3. Trigger one sync per source (each is rate-limited to one run
#    per 5 minutes per source), in this order:
curl -s -X POST https://cybermap-ai-backend.onrender.com/api/v1/ingestion/sync/nvd
curl -s -X POST https://cybermap-ai-backend.onrender.com/api/v1/ingestion/sync/kev
curl -s -X POST https://cybermap-ai-backend.onrender.com/api/v1/ingestion/sync/epss
curl -s -X POST https://cybermap-ai-backend.onrender.com/api/v1/ingestion/sync/mitre
```

(These calls need the logged-in session cookie — easiest is to use
the browser's DevTools "Copy as cURL" on the request, or run them
from an admin session. Without a key, NVD syncs at the anonymous
rate limit and is slow — set `NVD_API_KEY` first if you have one.)
After ingestion, the dashboard, explorer, graph and AI pages show
real data instead of the empty state.

## 4. Verification checklist (live)

- [ ] `GET /health` → `status: "ok"`, `database: "ok"`, `ai_mode: "fallback"`
- [ ] `GET /docs` → 404 in production (§1.3 applied)
- [ ] Frontend home page loads on the Vercel URL; no console errors
- [ ] Register → login → dashboard works in a real browser (§1.4/§1.5)
- [ ] A second user cannot open the first user's collection (expect 404)
- [ ] Ingestion ran; dashboard shows real CVE/KEV counts
- [ ] AI Analyse works in fallback mode (no provider key set)

Re-run the 23-step E2E walk from `docs/TESTING.md` §5 against the
live URLs once the site is up (the walk script itself was scratch
only and needs re-creating with fresh usernames per run).

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Build fails: `No module named 'psycopg2'` / `'psycopg'` | Driver not installed | §1.1 is already fixed (driver is in `requirements.txt`) — check the build log shows the install succeeding |
| Build fails: `Can't load plugin: sqlalchemy.dialects:postgres` | `DATABASE_URL` still `postgres://` | The startCommand rewrite (§1.2) should handle it — check the command wasn't edited; or set `DATABASE_URL` manually in the dashboard as `postgresql+psycopg://…` |
| Build fails at Alembic: could not connect | `DATABASE_URL` not set yet | Set it in the Render dashboard (Step 2 step 3), then Manual Deploy → Deploy latest commit |
| `/health` says `database: "error"` | DB unreachable, `DATABASE_URL` unset, or Supabase project paused | Check the service logs; confirm `DATABASE_URL` is set in the Render dashboard (§1.9 step 3) and the Supabase project is not paused (§1.9 step 6); redeploy so Alembic re-runs |
| Migration fails on `CREATE EXTENSION vector` | Extension not enabled | Run `CREATE EXTENSION vector;` once in the Supabase SQL Editor, then redeploy (§1.9 step 5) |
| Site worked, now connection errors after ~a week idle | Supabase free-tier pause | Resume the project in the Supabase dashboard (§1.9 step 6) |
| Login/register return 403 | `CORS_ORIGINS` is not the Vercel origin | Step 5 — exact origin, no trailing slash |
| Login 200, then immediately logged out | Cookie `SameSite`/`Secure` wrong | §1.4 — must be `none` + `true` on this split-domain setup |
| Frontend shows "backend unreachable" | `NEXT_PUBLIC_API_URL` wrong or stale | It is baked at build time — fix the env var in Vercel and **redeploy** |
| First request very slow / 502 | Free-tier cold start | Normal on the free plan (~30–60 s). Use the Starter plan to stay warm |
| Dashboard empty after deploy | Fresh DB, no ingestion yet | Step 6 |
| CI checks failing on GitHub | Stale runs from before the code was pushed | CI is green as of run #6 (commit 55d3cdb, both jobs passed) — the old 0/2 failures were from a commit before `backend/` and `frontend/` existed in the repo |

## 6. Rollback

- **Frontend:** Vercel dashboard → Deployments → pick the previous
  good deployment → **Promote to Production**.
- **Backend:** Render dashboard → `cybermap-ai-backend` →
  **Manual Deploy → Deploy** an earlier commit, or
  `git revert` the breaking commit and push (Render auto-deploys).
- **Database:** Alembic downgrade is available
  (`alembic downgrade -1` from `backend/`), but do not run it
  against live data without a backup — the Supabase free tier has
  no automatic backups, so export first (`pg_dump` with the
  Supabase connection string).
