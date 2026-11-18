# CyberMap AI — Deployment Guide (Vercel + Render)

> **Status:** configs prepared 2026-11-18. **Not yet deployed.** This
> guide is the deploy runbook for the setup the project owner chose:
> frontend on Vercel, backend + Postgres on Render — the same split
> as Curion. The three deploy files are `vercel.json`, `render.yaml`
> (both at the repo root) and this guide.
>
> ⚠️ **Do not skip §1.** Two real bugs were found while preparing
> these configs; the workarounds are baked into `render.yaml`, and
> one pre-deploy code change (§1.3) is still required before the
> site can be public.

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
    │  DATABASE_URL (Postgres + pgvector)
    ▼
Render — managed PostgreSQL 16 + pgvector (cybermap-db)
```

The frontend and backend are on **different sites** (`vercel.app`
vs `onrender.com`). That one fact drives the two most important
settings in this guide: the session cookie must be
`SameSite=None; Secure` (§1.4) and `CORS_ORIGINS` must list the exact
Vercel URL (§1.5). Get either wrong and login silently breaks.

## 1. Pre-deploy blockers — read before touching any dashboard

### 1.1 Postgres driver missing from `requirements.txt` (verified)

`backend/requirements.txt` contains **no Postgres driver**
(`psycopg2` / `psycopg`). Verified locally in the project venv —
every URL form fails:

- `postgresql+psycopg2://…` → `ModuleNotFoundError: No module named 'psycopg2'`
- `postgresql+psycopg://…` → `ModuleNotFoundError: No module named 'psycopg'`
- `postgresql://…` → same `psycopg2` error (it is the default driver)

So the backend **cannot connect to Postgres as written** — not on
Render, not in Docker Compose either (the Docker path has the same
hole). Workaround already in `render.yaml`: the build command
installs `psycopg[binary]==3.2.10` alongside `requirements.txt`.
**Durable fix (do this):** add `psycopg[binary]==3.2.10` to
`backend/requirements.txt` and then drop the extra install from the
build command.

### 1.2 Render's `DATABASE_URL` scheme is rejected by SQLAlchemy 2.0 (verified)

Render issues connection strings as `postgres://user:pass@host/db`.
SQLAlchemy 2.0 removed the `postgres://` alias — verified locally:

- `postgres://…` → `NoSuchModuleError: Can't load plugin: sqlalchemy.dialects:postgres`

Workaround already in `render.yaml`: the start command rewrites a
leading `postgres://` to `postgresql+psycopg://` before launching
uvicorn (a no-op if the URL already has the right scheme).
**Durable fix (optional):** normalize the scheme in
`backend/app/core/config.py` when `database_url` is loaded, e.g.
`if url.startswith("postgres://"): url = "postgresql+psycopg://" + url[len("postgres://"):]`.

### 1.3 `/docs`, `/redoc`, `/openapi.json` are public — CODE CHANGE REQUIRED

`backend/app/main.py` sets `docs_url="/docs"` unconditionally; no
environment flag gates it. `ENVIRONMENT=production` (already set in
`render.yaml`) changes nothing on its own. This is residual risk R4
in `docs/SECURITY.md`. **Before the site is public, apply this
change** (or keep the deployment link private until it is applied):

```python
# backend/app/main.py — inside create_app(), replace the FastAPI(...)
# call's docs arguments with:
docs_url="/docs" if settings.environment != "production" else None,
redoc_url="/redoc" if settings.environment != "production" else None,
openapi_url="/openapi.json" if settings.environment != "production" else None,
```

(`openapi_url=None` matters too — disabling only `docs_url` still
leaves the raw `/openapi.json` map public.) After the change, commit,
push, and Render redeploys automatically. Verify with
`curl -s -o /dev/null -w "%{http_code}" https://<backend>/docs`
— expect **404** in production.

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
Set it to the real Vercel origin (no trailing slash) in Step 4.

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

### 1.8 Cost (approximate — verify at render.com/pricing)

| Piece | Plan in these configs | Approx. cost |
|---|---|---|
| Render web service | `free` (spins down after ~15 min idle; first request after sleep is slow) | $0 |
| Render Postgres | `basic-256mb` (cheapest always-on; the free tier expires after 30 days) | ~$6/mo + ~$0.30/GB/mo storage |
| Vercel frontend | Hobby | $0 |
| **Total, always-on backend** | Starter web service (~$7/mo) + Basic-256mb Postgres | **~$13/mo + storage** |

Switch the web service to `plan: starter` in `render.yaml` (or in
the dashboard) if cold starts are unacceptable.

## 2. Environment variables

### Render — backend (`cybermap-ai-backend`)

Set by `render.yaml` on Blueprint apply, except the `sync: false`
rows, which you set in the dashboard (leave empty for fallback mode).

| Variable | Value | Notes |
|---|---|---|
| `ENVIRONMENT` | `production` | Drives the §1.3 docs gate once applied |
| `SECRET_KEY` | *(generated by Render)* | Session signing. Never commit a value |
| `DATABASE_URL` | *(from `cybermap-db`)* | Scheme rewritten at start (§1.2) |
| `CORS_ORIGINS` | `https://YOUR-VERCEL-APP.vercel.app` → **replace with the real Vercel URL in Step 4** | Exact origin, no trailing slash (§1.5) |
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

(And apply the §1.3 docs-gating code change in the same push if it
is ready — otherwise do it before announcing the site publicly.)

### Step 1 — Render: create the Blueprint

1. Render dashboard → **New → Blueprint** → select the
   `sahilm4711-cyber/CYBERMAP.AI` repo.
2. Render shows two resources from `render.yaml`:
   `cybermap-ai-backend` (web service) and `cybermap-db` (Postgres).
   Confirm the database plan is `basic-256mb` and apply.
3. Watch the first build log. It must show `pip install` succeeding
   and then Alembic running migration `0001_initial` — that
   migration runs `CREATE EXTENSION IF NOT EXISTS vector`
   (pgvector is available on Render Postgres but not enabled by
   default; the migration enables it). If the migration fails on
   the extension, open the database's psql shell in the Render
   dashboard, run `CREATE EXTENSION vector;` once, and redeploy.
4. If the build fails at the Alembic step with a connection error,
   wait until the database shows **Available**, then **Manual
   Deploy → Deploy latest commit** — the database is created just
   before the service builds on the first Blueprint apply.

### Step 2 — Verify the backend

```bash
BACKEND=https://cybermap-ai-backend.onrender.com
curl -s $BACKEND/health
# expect: {"status":"ok", ... "database":"ok", "ai_mode":"fallback", ...}
curl -s $BACKEND/
# expect: {"service":"cybermap-ai", "version":"0.1.0", ...}
curl -s -o /dev/null -w "%{http_code}\n" $BACKEND/docs
# expect: 404 once §1.3 is applied (200 before that — not yet gated)
```

`database: "error"` here means the backend is up but cannot reach
Postgres — check the logs for the driver/scheme issues in §1.1–1.2.
On the free web-service plan the first request after idle takes
~30–60 s (cold start); that is normal, not an error.

### Step 3 — Vercel: deploy the frontend

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

### Step 4 — Point the backend at the real frontend URL

1. In Render, open `cybermap-ai-backend` → **Environment** → set
   `CORS_ORIGINS` to the exact Vercel origin, e.g.
   `https://cybermap-ai.vercel.app` (no trailing slash).
2. Save — Render redeploys the service automatically.
3. End-to-end check in a real browser: register → log in →
   dashboard loads → open a CVE → add it to a collection →
   log out → `/me` asks for login again. If login returns 403,
   `CORS_ORIGINS` is wrong (§1.5). If login succeeds but the next
   page acts logged-out, the cookie settings are wrong (§1.4).

### Step 5 — Fill the database (admin ingestion)

Registration always creates role `user`; ingestion endpoints are
admin-only. Promote the first user, then sync each source once
(development guide `docs/DEVELOPMENT.md` §6 has the same steps for
local use):

```bash
# 1. In the Render dashboard, open the cybermap-db psql shell:
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
| Build fails: `No module named 'psycopg2'` / `'psycopg'` | Driver not installed | Check the build log shows the `psycopg[binary]==3.2.10` install; durable fix is §1.1 |
| Build fails: `Can't load plugin: sqlalchemy.dialects:postgres` | `DATABASE_URL` still `postgres://` | The startCommand rewrite (§1.2) should handle it — check the command wasn't edited; or set `DATABASE_URL` manually in the dashboard as `postgresql+psycopg://…` |
| `/health` says `database: "error"` | DB unreachable or migration not run | Check the service logs; confirm the database is **Available**; redeploy so Alembic re-runs |
| Migration fails on `CREATE EXTENSION vector` | Extension not allow-listed for this DB | Run `CREATE EXTENSION vector;` once in the dashboard psql shell, then redeploy |
| Login/register return 403 | `CORS_ORIGINS` is not the Vercel origin | Step 4 — exact origin, no trailing slash |
| Login 200, then immediately logged out | Cookie `SameSite`/`Secure` wrong | §1.4 — must be `none` + `true` on this split-domain setup |
| Frontend shows "backend unreachable" | `NEXT_PUBLIC_API_URL` wrong or stale | It is baked at build time — fix the env var in Vercel and **redeploy** |
| First request very slow / 502 | Free-tier cold start | Normal on the free plan (~30–60 s). Use the Starter plan to stay warm |
| Dashboard empty after deploy | Fresh DB, no ingestion yet | Step 5 |
| CI checks failing on GitHub (0/2) | Pre-existing: the CI workflow fails on the repo | Unrelated to deploy, but check the workflow run — do not ignore failing checks on a public repo |

## 6. Rollback

- **Frontend:** Vercel dashboard → Deployments → pick the previous
  good deployment → **Promote to Production**.
- **Backend:** Render dashboard → `cybermap-ai-backend` →
  **Manual Deploy → Deploy** an earlier commit, or
  `git revert` the breaking commit and push (Render auto-deploys).
- **Database:** Alembic downgrade is available
  (`alembic downgrade -1` from `backend/`), but do not run it
  against live data without a backup — Render keeps automatic
  backups per its Postgres plan.
