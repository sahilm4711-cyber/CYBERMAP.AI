# CyberMap AI — Security Review (Phase 9)

> **Status:** Phase 9 review complete, 2026-11-18. Backend suite
> **197 tests passing** (179 pre-existing + 18 new Phase 9 tests),
> three consecutive full runs with zero failures. Frontend
> `npm run build` clean (14 pages) and `npm run lint` clean.
> Live end-to-end smoke walk against a copy of the dev DB: 23/23
> steps as expected (see §5).

## 1. Methodology

This review tested the **actual implementation**, not the design
documents. For each checklist item (§2) there is either:

- a **test that proves the control works** (named below, runnable —
  see §4), or
- a **fix made in this phase** plus the test that proves the fix, or
- a **code inspection** (grep / read) where the property is structural
  (e.g. "no raw SQL exists"), with the exact command recorded so it
  can be re-run.

Rules followed throughout: passive review only — no testing against
any system other than a local temp SQLite DB and a scratch copy of
the dev DB; no real credentials, no user data. The dev DB
(`backend/cybermap.db`) was never written to by tests; the live
smoke test ran against `/tmp/e2e/cybermap-e2e.db`, a copy.

## 2. Checklist results

| # | Item | Result | Evidence |
|---|---|---|---|
| 1 | Broken access control — ownership on research / AI endpoints | **Pass** | Re-ran Phase 3/6/8 isolation suites (all pass). New cross-user probes: `test_security_phase9.py::test_idor_other_users_objects_return_404` — user B gets 404 on A's collection, note, saved analysis and conversation, for both GET and DELETE. |
| 2 | Graph endpoints leak no private data | **Pass** | Graph nodes are public intel only. `test_graph_node_exposes_no_private_data`: with A's collection + note in the DB, B's `GET /graph/node/vulnerability/{cve}` returns only the public fields (`cve_id`, `description`, `severity`, `cvss_*`, `published_at`, `source`, `source_url`); no collection/note text appears. |
| 3 | Password minimum (8) enforced | **Pass** | Pydantic (`RegisterRequest` / `PasswordChangeRequest`, min length 8) + service check (`auth_service._validate_new_password`). Existing `test_auth.py::test_register_weak_password_rejected` passes. |
| 4 | Weak / common passwords rejected | **Fix + Pass** | **Was missing:** any 8+ character password was accepted, including breached-list ones. **Fix:** `app/services/auth_service.py` — `COMMON_PASSWORDS` denylist (case-insensitive) + reject password == username, applied on register and password change. Test: `test_common_passwords_rejected_on_register`, `test_common_password_rejected_on_change` (422 for `password`, `password123`, `12345678`, `qwerty123`). |
| 5 | Login rate limiting | **Fix + Pass** | **Was missing:** no login rate limiting existed. **Fix:** `app/security/rate_limit.py` — max **10 failed logins per identifier per 15 minutes** (in-memory, thread-safe), 429 when hit; success clears the counter; unknown users count too (no enumeration signal). Wired into `POST /api/v1/auth/login`. Tests: `test_login_rate_limit_blocks_after_10_failures` (11th attempt 429 even with the right password; other identifiers unaffected), `test_successful_login_resets_failure_counter`. |
| 6 | Session fixation / logout / password-change revocation | **Pass** | Login mints a fresh random token every time (`auth_service.create_session` + `sessions.new_token`). New test `test_login_issues_fresh_token_each_time`: a planted pre-login cookie value is replaced, and two logins give different tokens. Logout revokes (`test_auth.py::test_logout_revokes_session`); password change revokes other sessions (`test_auth.py::test_password_change_revokes_other_sessions`). |
| 7 | SQL injection | **Pass** | Inspection: `grep -rn "text(\|\.execute(" backend/app` — the only `execute` calls are the static `PRAGMA foreign_keys=ON` and the Phase 9 health `SELECT 1` (both constant strings, no interpolation). All other queries are SQLAlchemy ORM filters with bound parameters. No f-string SQL, no `text()` with user input. |
| 8 | XSS — frontend `dangerouslySetInnerHTML` | **Pass** | Inspection: `grep -rn dangerouslySetInnerHTML frontend/` — zero occurrences. All user/DB content is rendered as React text. |
| 9 | XSS — API reflecting untrusted input in errors | **Pass** | Error details are static strings or validated field values. The one place user input appears in an error is `unknown CVE: {cve_id!r}` / `unknown source: {source!r}` (JSON string in a JSON body — no HTML context, no script execution). 500 bodies are generic (see #12). |
| 10 | CSRF — cross-site state-changing requests | **Fix + Pass** | **Residual hole found:** cookie is `SameSite=Lax`, which blocks cross-site `fetch` but **allows cookies on top-level navigation POSTs** (e.g. an auto-submitted form on an attacker's page hitting `/logout` or `/research/collections`). **Fix:** `app/security/csrf.py` — `verify_origin` dependency: for POST/PUT/PATCH/DELETE, a present `Origin` header must be in the CORS allow-list (else 403); if no `Origin`, a present `Referer` origin must be in the list; requests with neither header (curl, server-to-server, tests) are allowed. Attached as a router dependency to all five routers with state-changing routes (auth, ai, research, ingestion, graph). `app/main.py` was not edited (coordinator-owned); the router-level dependency is the equivalent enforcement. Tests: `test_cross_origin_login_post_blocked`, `test_cross_origin_referer_post_blocked`, `test_safe_methods_unaffected_by_origin`, `test_cross_origin_research_post_blocked`. |
| 11 | IDOR — every `{id}` path param | **Pass** | Same probes as #1, plus `test_research.py` / `test_ai_chat_api.py` isolation tests (re-run, passing). Ingestion jobs are admin-only (`require_role("admin")`). |
| 12 | Sensitive data exposure — responses | **Pass** | `UserResponse` carries no `password_hash`; sessions store only the SHA-256 hash, never the raw token (`test_login_success_sets_http_only_cookie`). New test `test_no_sensitive_fields_in_auth_and_docs`: `/me`, `/openapi.json` and `/docs` contain no `password_hash` / `session_token` strings. |
| 13 | Sensitive data exposure — error bodies | **Pass** | New test `test_500_response_contains_no_traceback`: a route raising `RuntimeError` returns 500 with the generic `{"detail": "Internal Server Error"}` body — no traceback, no exception message. (FastAPI default handler, `debug=False`.) |
| 14 | SSRF — server-side requests to user URLs | **Pass** | Inspection: all `httpx` calls go to fixed provider/source URLs (NVD, KEV, EPSS, MITRE, configured AI providers) or a test-injected client. No endpoint accepts a URL from the caller. Ingestion sync takes only a source **name** from an allow-list (`SYNC_SOURCES`); new test `test_ingestion_sync_rejects_arbitrary_source` — `bogus`, `NVD`, `nvd;rm`, `evil-feed` all 404 (admin). |
| 15 | Rate-limit bypass — AI analyse (10/hour/user) | **Pass** | The limit counts `saved_analyses` rows per user in the last hour (`analyst._check_rate_limit`), not conversations. New test `test_ai_analyze_limit_not_bypassed_by_new_conversation`: 10 analyses → 200, 11th → 429, opening a new conversation + analysing again → still 429. |
| 16 | Rate-limit bypass — ingestion sync (5 min/source) | **Pass** | Existing `test_ingestion_api.py::test_sync_second_immediate_trigger_gets_429` re-run and passing. New test `test_ingestion_sync_guard_blocks_second_run_within_5_minutes`: a finished job < 5 min ago blocks a new sync with 429 (no network involved). |
| 17 | Prompt injection in retrieved content | **Pass** | Re-ran Phase 6 tests: `test_ai_rag.py::test_grounded_prompt_wraps_context_in_delimiters` (chunks inside `<retrieved_context>` tags + safety instruction) and `test_ai_chat_api.py::test_chat_injection_chunk_never_obeyed` (fallback answer built from DB record facts, never obeys or echoes the injected instruction). Fallback chat resolves RAG hits back to DB records and reports structured facts only. |
| 18 | Unsafe logging | **Pass** | Inspection: `grep -rni "log.*password\|log.*token\|log.*secret\|log.*api_key\|log.*authorization" backend/app` — only docstring statements that secrets are *never* logged. Audit log details contain usernames and counts only (`auth_service`, `audit`). |
| 19 | Insecure config — CORS / debug / cookies / `.env.example` | **Pass** | CORS allow-list is explicit (`cors_origins`, default `http://localhost:3000`, no `*`). `debug=False` by default. `SESSION_COOKIE_SECURE` is configurable (false for local HTTP, true in production). `.env.example` contains only placeholders (`<redacted>` values, `change-me-…`, empty keys). |
| 20 | **Known wart: `/health` reports `database: "not_configured"`** | **Fix + Pass** | **Fix:** `app/api/v1/health.py` now runs a real `SELECT 1` via the request DB session and reports `"ok"` / `"error"`; overall `status` stays `"ok"` when the DB is down (the process is up; callers needing the DB should check the `database` field). Schema description updated (`app/schemas/health.py`). **Stale tests updated:** `tests/test_health.py` — the Phase 2 assertion is now `database == "ok"`, plus new `test_api_v1_health_reports_database_ok` and `test_health_reports_error_when_database_unreachable` (bad-path engine → 200 with `database: "error"`). Live check: the E2E server against the dev DB copy returned `"database": "ok"`. |
| 21 | `/docs` leaks nothing sensitive | **Pass** | See #12 — `/docs` and `/openapi.json` contain no hashes, tokens or keys. (Note: `/docs` itself is public by design; see residual risk R4.) |

## 3. Fixes made in this phase (summary)

| Fix | File(s) | Proving test |
|---|---|---|
| Real DB health check (`SELECT 1`, `ok`/`error`) | `backend/app/api/v1/health.py`, `backend/app/schemas/health.py` | `tests/test_health.py` (updated + 2 new) |
| Login rate limit, 10 failed / 15 min / identifier → 429 | `backend/app/security/rate_limit.py` (new), `backend/app/api/v1/auth.py` | `tests/test_security_phase9.py` (2 tests) |
| Common-password denylist + reject password == username | `backend/app/services/auth_service.py` | `tests/test_security_phase9.py` (2 tests) |
| Origin/Referer CSRF check on all state-changing routes | `backend/app/security/csrf.py` (new); dependency added to `auth.py`, `ai.py`, `research.py`, `ingestion.py`, `graph.py` | `tests/test_security_phase9.py` (4 tests) |
| Login + register pages (were missing entirely) | `frontend/app/login/page.tsx`, `frontend/app/register/page.tsx`, `frontend/lib/services/auth.ts` | `npm run build` (14 pages), `npm run lint` clean |
| AI assistant chat page (was missing) | `frontend/app/ai-assistant/page.tsx`, `frontend/lib/services/ai.ts` | `npm run build`, `npm run lint` clean |
| Real navigation in root layout (was placeholder spans) | `frontend/app/layout.tsx` (nav only) | `npm run build`, `npm run lint` clean |

No other backend behaviour was changed. Nothing was pushed to
GitHub; no repo was created.

## 4. How to run the security tests

```bash
cd backend
.venv/bin/python -m pytest tests/test_security_phase9.py tests/test_health.py tests/test_auth.py -q
# Full suite (197 tests, ~75 s):
.venv/bin/python -m pytest tests/ -q
# Frontend:
cd ../frontend && npm run build && npm run lint
```

The Phase 6 prompt-injection tests live in
`tests/test_ai_rag.py` and `tests/test_ai_chat_api.py` and run as
part of the full suite.

## 5. QA verification (Phase 9)

- **Backend suite:** 197 passed, 0 failed, three consecutive full
  runs (runs 1–3 all green; the previously seen flakes in
  `test_ingestion_parsers` / `test_ingestion_run` NVD tests and
  `test_intelligence::test_metrics_explained` did **not** reproduce
  in any of the three runs, including three extra runs of just those
  files — no root cause found because there was no failure to root
  cause; the tests use fixture-local mocked transports and temp DBs,
  with no shared state).
- **Frontend:** `npm run build` clean — 14 pages (was 11; new:
  `/login`, `/register`, `/ai-assistant`). `npm run lint` clean, zero
  errors. Grep for `Math.random` / fake data in `frontend/app`,
  `components`, `lib`: nothing — every page fetches the backend;
  the only CVE-like strings are example text in input placeholders.
- **Live E2E smoke walk** (uvicorn on scratch port 8129, copy of the
  dev DB — 50 CVEs, 984 CWE, 706 techniques, 1782 KEV, 48 EPSS):
  23/23 steps as expected — register → login → dashboard summary →
  search CVE → CVE detail → graph → AI analyse (fallback) → chat
  (answer cites the CVE) → create collection → add item → note →
  compare 2 CVEs → export JSON → export CSV → logout → `/me` 401 →
  dashboard 401 → user B register/login → B GET A's collection 404
  → B GET A's note 404 → B graph node 200 (public intel). Walk
  script: `/tmp/e2e/walk.py` (ephemeral; re-runnable with fresh
  usernames per run).

## 6. Residual risks (not fixed in this phase)

- **R1 — Login rate limit is in-memory and per-process.** It does
  not survive a restart and is not shared across workers. A
  multi-worker / multi-replica production deployment must move it
  to Redis (same for the ingestion 5-minute guard, which already
  uses the `ingestion_jobs` table and *is* shared). A distributed
  attacker can also spread guesses across many identifiers (10 per
  identifier is still the bound per account).
- **R2 — No CAPTCHA / no account lockout.** The rate limit slows
  guessing to 10 tries per 15 minutes per identifier; a slow,
  distributed password-spraying attack is still possible. Add
  CAPTCHA on login and alerting on repeated 429s before exposing
  registration publicly.
- **R3 — CSRF check trusts the absence of headers.** Requests with
  neither `Origin` nor `Referer` are allowed (curl, server-to-server
  calls, and some privacy-hardened browsers). The check only rejects
  requests that positively identify as cross-origin. The primary
  defence remains `SameSite=Lax` + the check together. A global
  middleware version belongs in `app/main.py` (coordinator-owned)
  if the router-level dependency is ever removed.
- **R4 — `/docs`, `/redoc`, `/openapi.json` are public.** They
  expose the full endpoint map (no secrets — verified in #12), but
  they advertise the attack surface. Gate them behind auth or
  `ENVIRONMENT=production` before any public deployment.
- **R5 — No per-IP throttling on other endpoints.** Only login,
  AI analyse and ingestion sync are rate-limited. Registration,
  chat and research writes have no limits; add IP-based throttling
  at the reverse proxy before public exposure.
- **R6 — Session cookie `Secure` is off by default**
  (`SESSION_COOKIE_SECURE=false` for local HTTP development). It
  must be `true` in production, and the app must run behind HTTPS;
  otherwise the session token can be captured on the network.
- **R7 — Common-password list is small and static.** The denylist
  covers the worst offenders only. For stronger protection, check
  passwords against a breached-password service (e.g. Have I Been
  Pwned k-anonymity API) at registration.
- **R8 — No Docker / Postgres / Redis in this VM.** The suite runs
  against SQLite; Postgres + pgvector behaviour (vector search,
  `tsvector`, concurrent ingestion) is unverified here and must be
  checked on the deployment target.
