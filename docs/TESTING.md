# CyberMap AI — Testing Guide

> **Status:** Phase 10. Backend suite **197 tests, all passing**
> (verified 2026-11-18, three consecutive full runs in Phase 9
> plus the Phase 10 final run). Frontend `npm run build` clean
> (14 pages) and `npm run lint` clean. This document tells you how
> to run everything, what each test file covers, and what is
> honestly still unverified.

## 1. Backend tests (pytest)

```bash
cd backend
.venv/bin/python -m pytest tests -q
```

- Full suite: **197 tests**, ~75 s on this machine.
- `pytest.ini` sets `testpaths = tests`, `python_files = test_*.py`,
  `addopts = -q`.
- Tests run against **fresh temporary SQLite databases** (one per
  test, via fixtures in `tests/conftest.py`) — the dev database
  `backend/cybermap.db` is **never written to by tests**. Ingestion
  tests use mocked transports and fixture data, never live APIs.
- Run one file: `.venv/bin/python -m pytest tests/test_auth.py -q`
- Run one test: `.venv/bin/python -m pytest tests/test_auth.py::test_register_weak_password_rejected -q`
- Collect only (count tests without running):
  `.venv/bin/python -m pytest tests --collect-only -q`

### What each test file covers (counts from `--collect-only`, 2026-11-18)

| File | Tests | Covers |
|---|---|---|
| `test_health.py` | 7 | Root `/` and `/health` / `/api/v1/health`; Phase 9 real DB check (`SELECT 1` → `database: "ok"`, and `"error"` when the DB is unreachable) |
| `test_auth.py` | 15 | Register / login / logout / `/me` / password change; Argon2id hashing; HTTP-only session cookie; weak-password rejection; logout and password-change session revocation |
| `test_isolation.py` | 7 | Data isolation (Phase 3, critical): a user cannot see or touch another user's data; admin guard |
| `test_models.py` | 19 | All 21 SQLAlchemy models: fields, defaults, relationships, constraints |
| `test_migrations.py` | 1 | Alembic upgrade head → downgrade base → upgrade head on a fresh SQLite file |
| `test_ingestion_parsers.py` | 15 | NVD / KEV / EPSS / MITRE ATT&CK / CWE parsers on mocked fixture data (never live APIs) |
| `test_ingestion_run.py` | 8 | Ingestion orchestration: dedup, safe upserts, job logging, error handling |
| `test_ingestion_api.py` | 8 | `GET /ingestion/status`, `GET /ingestion/jobs`, `POST /ingestion/sync/{source}` (admin-only, 5-minute guard, unknown-source 404) |
| `test_dashboard.py` | 6 | `GET /dashboard/summary` and `/trends`: counts, date-range filter, severity/CWE breakdowns |
| `test_vulnerabilities.py` | 10 | Explorer search / filters / sort / pagination; CVE detail; related CVEs; 404 on unknown CVE |
| `test_intelligence.py` | 5 | KEV list, EPSS ranking, timeline, metrics explainer |
| `test_ai_adapters.py` | 12 | OpenAI / Groq / Gemini adapters with mocked `httpx` transports; no real provider is ever hit; error mapping to `AIProviderError` |
| `test_ai_analyst.py` | 8 | Analyst: fallback (rule-based) analysis, mocked-provider analysis, provider-error fallback, exact 10-section structure |
| `test_ai_rag.py` | 9 | Embeddings + RAG: chunking, local-hash fallback embedding, SQLite cosine ranking, grounded-prompt delimiters (`<retrieved_context>`) |
| `test_ai_chat_api.py` | 17 | Assistant chat API + AI API: chat, conversations (list/get/delete, owner-only 404), prompt-injection chunk never obeyed, AI analyse rate limit not bypassed by a new conversation |
| `test_graph.py` | 13 | Graph API: seed graph, search, CWE→techniques, node detail, expand; graph nodes expose no private data |
| `test_research.py` | 15 | Collections / items / bookmarks / notes / saved analyses / compare / export; owner-only 404s; collection status via status-tagged notes |
| `test_learning.py` | 6 | Learning topics list + detail; unknown slug 404; related real records |
| `test_security_phase9.py` | 16 | Phase 9 security checklist proofs: common-password denylist, login rate limit (10/15 min → 429), CSRF Origin/Referer check, IDOR 404 probes, no sensitive fields in auth/docs responses, 500 body contains no traceback, ingestion sync rejects arbitrary sources |
| **Total** | **197** | |

### Test data rules

- No real credentials, no user data, no live network calls in
  tests. Provider calls are mocked; ingestion uses fixtures.
- The one test fixture password you will see in the code is
  `correct-horse-battery` (and similar obvious test strings).
  These are **test-only fixtures**, not real credentials — they
  are intentionally left in place and are excluded from the
  secret scan (see §6).

## 2. Frontend checks

```bash
cd frontend
npm run build     # production build — must succeed, 14 pages
npm run lint      # ESLint — must be clean, zero errors
```

- `npm run build` reports **14 pages** (11 `page.tsx` files plus
  Next.js-generated routes). Pages: `/`, `/login`, `/register`,
  `/dashboard`, `/vulnerabilities`, `/vulnerability/[cveId]`,
  `/intelligence`, `/attack-graph`, `/ai-assistant`, `/research`,
  `/learning`.
- There is **no frontend unit-test suite yet** and no Playwright
  E2E suite wired into the repo — the E2E walk in §5 was run by
  hand against the live API with a script (see below). Adding
  Playwright is a post-Phase-10 task.
- Grep check (Phase 9): no `Math.random` / fake data in
  `frontend/app`, `components`, `lib` — every page fetches the
  backend; the only CVE-like strings are example text in input
  placeholders.

## 3. Full-stack smoke test

Start the backend against a **copy** of the dev DB (never the
real `backend/cybermap.db`), then hit it from the frontend or
curl:

```bash
# 1. Copy the dev DB so the smoke test cannot touch real data
mkdir -p /tmp/e2e
cp backend/cybermap.db /tmp/e2e/cybermap-e2e.db

# 2. Start uvicorn on a scratch port against the copy
cd backend
DATABASE_URL=sqlite:////tmp/e2e/cybermap-e2e.db \
  .venv/bin/python -m uvicorn app.main:app --port 8129

# 3. Health check
curl -s http://localhost:8129/health
# {"status":"ok","service":"cybermap-ai",...,"database":"ok","ai_mode":"fallback"}

# 4. Frontend (separate terminal)
cd frontend
npm run dev     # http://localhost:3000 — point NEXT_PUBLIC_API_URL at :8129 if needed
```

Phase 9 ran this exact smoke test: **23/23 steps as expected**
(see §5).

## 4. Known flaky-test history — stated honestly

Two tests failed **once each** in intermediate runs during
Phases 4–9 and then passed in **3+ consecutive full runs**
afterwards, including three extra runs of just those files:

1. Ingestion NVD parser tests (`test_ingestion_parsers` /
   `test_ingestion_run`) — one failure in an intermediate run.
2. `test_intelligence::test_metrics_explained` — one failure in
   an intermediate run.

**Root cause was never reproduced and never found.** The tests
use fixture-local mocked transports and temp DBs with no shared
state, so there was no failure left to root-cause. They are not
marked flaky, not skipped, and not quarantined — they run in the
full suite every time. If either fails again, do not dismiss it:
capture the full output (`pytest tests/<file> -v --tb=long`),
note the run, and investigate before re-running.

## 5. The E2E smoke walk (23/23, Phase 9)

Run live against a copy of the dev DB (50 CVEs, 984 CWE,
706 techniques, 1782 KEV, 48 EPSS) on scratch port 8129.
Walk script (ephemeral, re-runnable with fresh usernames per
run): `/tmp/e2e/walk.py` — it was a scratch script, not committed
to the repo; recreate it from this list if needed.

| # | Step | Expected | Result |
|---|---|---|---|
| 1 | Register user A | 201 + user object | ✅ |
| 2 | Login user A | 200 + HTTP-only cookie | ✅ |
| 3 | `GET /dashboard/summary` | Real counts from DB | ✅ |
| 4 | Search CVEs | Results, paginated | ✅ |
| 5 | CVE detail | Full record (CVSS, CWE, EPSS, KEV) | ✅ |
| 6 | Graph for the CVE | Nodes + edges | ✅ |
| 7 | AI analyse (fallback) | 10-section analysis, `ai_mode: fallback` | ✅ |
| 8 | Chat about the CVE | Answer cites the CVE | ✅ |
| 9 | Create collection | 201 | ✅ |
| 10 | Add item to collection | 201 | ✅ |
| 11 | Create note | 201 | ✅ |
| 12 | Compare 2 CVEs | Side-by-side rows | ✅ |
| 13 | Export collection (JSON) | File download | ✅ |
| 14 | Export collection (CSV) | File download | ✅ |
| 15 | Logout | 200, cookie cleared | ✅ |
| 16 | `GET /me` after logout | 401 | ✅ |
| 17 | `GET /dashboard/summary` after logout | 401 | ✅ |
| 18 | Register user B | 201 | ✅ |
| 19 | Login user B | 200 | ✅ |
| 20 | B `GET` A's collection | 404 (not 403) | ✅ |
| 21 | B `GET` A's note | 404 (not 403) | ✅ |
| 22 | B graph node for a public CVE | 200, public fields only | ✅ |
| 23 | (implicit) B sees none of A's private data anywhere | — | ✅ |

**23/23 steps as expected.** The walk was re-run as part of the
Phase 10 final verification (see `docs/TESTING_REPORT.md`).

## 6. Secret scan (run before every push)

```bash
cd ~/workspace/cybermap-ai
grep -rInE 'sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY' \
  --exclude-dir=.venv --exclude-dir=node_modules --exclude-dir=.next \
  --exclude-dir=__pycache__ --exclude-dir=.pytest_cache \
  --exclude-dir=cache backend app frontend docs .env.example \
  docker-compose.yml infrastructure 2>/dev/null
```

Also scan for hard-coded assignments
(`password\s*=\s*['"][^'"]+['"]`, `api_key\s*=\s*['"][^'"]`)
and eyeball the hits: **test fixture passwords** (e.g.
`correct-horse-battery`) and **placeholders** (`change-me-…`,
`<your-...>` in `.env.example`) are expected and stay. Anything
real must be removed before pushing. Phase 10 scan result: see
`docs/TESTING_REPORT.md` §5.

## 7. What is NOT tested (honest gaps)

- **No real-browser click-test** of the login / register /
  AI-assistant pages. `npm run build` proves the pages compile;
  nobody has clicked through them in a browser yet. Do this on
  the developer machine after the push.
- **Provider-mode AI untested without keys.** All provider tests
  use mocked transports. Real OpenAI / Groq / Gemini calls have
  never been made from this codebase; the fallback path is the
  only one verified end-to-end.
- **Postgres + pgvector untested here.** The suite runs on
  SQLite. Vector search, `tsvector`, concurrent ingestion and the
  HNSW index have not been exercised in this VM (no Docker /
  Postgres here). The HNSW index itself is **not yet created** —
  see `docs/TESTING_REPORT.md` §6.
- **Docker Compose never run here.** See `docs/DEVELOPMENT.md` §3.
- **No frontend unit tests, no Playwright suite** in the repo yet.
- **No load / concurrency testing** (single-process uvicorn,
  in-memory login rate limiter — see `docs/SECURITY.md` R1).
