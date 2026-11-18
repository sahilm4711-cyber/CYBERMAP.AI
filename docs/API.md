# CyberMap AI — API Reference

> **Status:** Phase 10. Complete REST reference for the Phase 10
> backend. Every route below was taken from the live application
> (`create_app()` route table, 2026-11-18), not from the design
> documents — if the code and this document ever disagree, the code
> wins and this document is stale.
>
> **Base URL (local dev):** `http://localhost:8000`
> **Interactive docs:** `http://localhost:8000/docs` (Swagger UI),
> `http://localhost:8000/redoc`, `http://localhost:8000/openapi.json`
>
> **Route count:** 50 routes in the live app — 49 under `/api/v1`
> plus the service root `GET /`. (`/docs`, `/redoc` and
> `/openapi.json` are FastAPI's own routes and are not counted in
> the 50.)

## 1. How to call the API

### Authentication — session cookie, not a token header

There is **no bearer token and no API key**. Authentication is a
server-side session:

1. `POST /api/v1/auth/register` (or `/login`) returns the user and
   sets an **HTTP-only** cookie named `cybermap_session`
   (name configurable via `SESSION_COOKIE_NAME`).
2. Every later request must send that cookie. Browsers do this
   automatically; `curl` needs `-c cookies.txt` on login and
   `-b cookies.txt` afterwards.
3. The cookie value is a random token; the database stores only its
   SHA-256 hash. `POST /api/v1/auth/logout` revokes the session.
   Changing your password revokes all *other* sessions.

> **CSRF note (Phase 9):** for `POST` / `PUT` / `PATCH` / `DELETE`
> requests on the `auth`, `ai`, `graph`, `ingestion` and `research`
> routers, a present `Origin` header must be in the CORS
> allow-list (default `http://localhost:3000`) or the request is
> rejected with **403**. A present `Referer` is checked the same
> way when there is no `Origin`. Requests with **neither** header
> (curl, server-to-server, tests) are allowed. `GET` requests are
> never affected. See `docs/SECURITY.md` §2 item 10.

### Response envelope — there is none

Responses are returned **directly**, with no wrapping `data` /
`success` / `error` envelope. A successful list returns either:

- a **page object** — `{"items": [...], "total": N, "page": P,
  "per_page": N, "pages": N}` (vulnerabilities, intelligence), or
- a **skip/limit object** — `{"items": [...], "total": N,
  "skip": N, "limit": N}` (research lists, ingestion jobs,
  AI conversations), or
- a single object / a bare JSON array (detail endpoints, graph).

Errors are always FastAPI's standard shape:

```json
{ "detail": "human-readable message" }
```

with the HTTP status code carrying the meaning (§3).

### Pagination — two conventions (this is real, not a typo)

| Convention | Endpoints | Params | Defaults |
|---|---|---|---|
| `page` / `per_page` | `/vulnerabilities`, `/intelligence/kev`, `/intelligence/epss-ranking` | `page` ≥ 1, `per_page` 1–100 | `page=1`, `per_page=20` |
| `skip` / `limit` | `/research/*` lists, `/ingestion/jobs`, `/ai/conversations` | `skip` ≥ 0, `limit` 1–100 (research: max 100; AI conversations: max 100; ingestion jobs: max 100) | `skip=0`, `limit=20` (research: 50) |

`per_page` / `limit` above 100 is rejected with **422**.

### Sorting

Only the vulnerability list sorts. `sort` accepts exactly one of
`newest` (default), `oldest`, `severity`, `cvss`, `epss`, `risk`
(EPSS desc, then CVSS desc). Any other value is **422**
(`unknown sort: ...`). All other list endpoints have a fixed
order, documented per endpoint (usually newest first).

### Common error codes

| Code | Meaning | When you will see it |
|---|---|---|
| 400 | Bad request | (not used by these routes today) |
| 401 | Unauthenticated | No session cookie, expired/revoked session, wrong password on login |
| 403 | Forbidden | Cross-origin state-changing request (CSRF check, §1); or a role check that returns 403 — note that **ownership** failures return **404**, not 403, by design (see below) |
| 404 | Not found | Unknown CVE / CWE / technique / collection / note / analysis / conversation / ingestion source — **and** another user's private object (IDOR protection: ownership cannot be probed, so a foreign object looks identical to a missing one) |
| 422 | Validation error | Bad body/query (short password, unknown `sort`, unknown `analysis_type`, bad UUID, `per_page` > 100, question > 2000 chars, compare with < 2 or > 5 CVEs, export `format` other than `json`/`csv`) |
| 429 | Rate limited | > 10 failed logins / 15 min per identifier; > 10 AI analyses / hour per user; ingestion sync < 5 min after the previous run for the same source |

## 2. Route map (all 50)

| Group | Routes | Auth |
|---|---|---|
| Root / health | `GET /`, `GET /health`, `GET /api/v1/health` | No |
| Auth | 6 routes under `/api/v1/auth` | Mixed (see §4) |
| Dashboard | `GET /dashboard/summary`, `GET /dashboard/trends` | Yes |
| Vulnerabilities | 3 routes under `/api/v1/vulnerabilities` | Yes |
| Intelligence | 4 routes under `/api/v1/intelligence` | Yes |
| Graph | 5 routes under `/api/v1/graph` | Yes |
| AI | 6 routes under `/api/v1/ai` | Yes, except `/ai/status` (no auth) |
| Ingestion | 3 routes under `/api/v1/ingestion` | Yes; `/sync/{source}` is admin-only |
| Research | 16 routes under `/api/v1/research` | Yes (owner-only) |
| Learning | 2 routes under `/api/v1/learning` | Yes |

## 3. Root & health — no auth

### `GET /`

Service root. Returns:

```json
{
  "service": "cybermap-ai",
  "version": "0.1.0",
  "environment": "development",
  "docs": "/docs",
  "health": "/health"
}
```

### `GET /health` and `GET /api/v1/health`

Same payload on both paths. The `database` field is a **real**
check (Phase 9): the endpoint runs `SELECT 1` and reports `"ok"`
when it answers, `"error"` when it does not. `status` stays
`"ok"` while the process is up even if the database is down —
callers that need the database must look at `database`, not
`status`.

```json
{
  "status": "ok",
  "service": "cybermap-ai",
  "version": "0.1.0",
  "environment": "development",
  "timestamp": "2026-11-18T00:00:00Z",
  "database": "ok",
  "ai_mode": "fallback"
}
```

`ai_mode` is `"provider"` when an AI provider is configured,
otherwise `"fallback"`. Errors: none expected (200 even when the
database is down, with `database: "error"`).

## 4. Auth — `/api/v1/auth`

All auth routes except `/me`, `/logout`, `/change-password` and
`/admin/ping` are public (no session needed). Every route on this
router is subject to the CSRF Origin check (§1).

### `POST /api/v1/auth/register` — no auth, 201 on success

Body:

```json
{ "username": "professor", "email": "prof@example.com", "password": "correct-horse-battery" }
```

- `username`: 3–64 chars.
- `email`: valid email address.
- `password`: ≥ 8 chars (configurable via `PASSWORD_MIN_LENGTH`),
  and **not** on the common-password denylist (Phase 9:
  `password`, `password123`, `12345678`, `qwerty123`, …) and
  **not equal to the username** (case-insensitive).

Success (201) — the created user, role is always `user`
(registration can never create an admin):

```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "username": "professor",
  "email": "prof@example.com",
  "role": "user",
  "is_active": true,
  "created_at": "2026-11-18T00:00:00Z",
  "last_login_at": null
}
```

No `password_hash` is ever returned. Errors: **422** (validation /
weak or common password), **409** (`Username or email already
registered`).

### `POST /api/v1/auth/login` — no auth, 200

Body: `{ "username": "professor", "password": "..." }` —
`username` also accepts an email address. Sets the HTTP-only
`cybermap_session` cookie and returns the same `UserResponse`
shape as register. A fresh session token is issued on **every**
login (no session fixation).

Errors: **401** (wrong credentials — and the message does not say
whether the username or the password was wrong), **422** (empty
fields), **429** after 10 failed logins per identifier per
15 minutes (the 11th attempt is rejected even with the correct
password; a successful login clears the counter).

### `POST /api/v1/auth/logout` — auth required, 200

Revokes the current session and clears the cookie. Returns
`{ "detail": "Logged out" }`. Errors: **401**.

### `GET /api/v1/auth/me` — auth required, 200

Returns the `UserResponse` shape for the logged-in user.
Errors: **401**.

### `POST /api/v1/auth/change-password` — auth required, 200

Body: `{ "current_password": "...", "new_password": "..." }`.
`new_password` follows the same rules as registration (≥ 8 chars,
not common, not equal to the username). **Revokes every other
session** of the user; the current session stays valid.

Success: `{ "detail": "Password changed", "sessions_revoked": 2 }`.
Errors: **401** (wrong current password / no session), **422**
(weak new password).

### `GET /api/v1/auth/admin/ping` — auth required, role `admin`

Admin-only probe. Returns `{ "detail": "admin ok: <username>" }`.
Errors: **401** (no session), **403** (logged in but not admin).

## 5. Dashboard — `/api/v1/dashboard` (auth required)

### `GET /api/v1/dashboard/summary`

Optional query params: `from=YYYY-MM-DD`, `to=YYYY-MM-DD`
(restricts the published counts and the recent list to CVEs
published in that range). Response:

```json
{
  "total_cves": 50,
  "critical": 3, "high": 18, "medium": 21, "low": 6,
  "none_severity": 0, "unknown_severity": 2,
  "kev_count": 12,
  "high_epss_count": 4,
  "recently_published": [
    { "cve_id": "CVE-2024-12345", "title": "...", "severity": "HIGH",
      "cvss_score": 8.1, "published_at": "2024-01-15T00:00:00Z" }
  ],
  "last_sync_at": "2026-11-17T10:00:00Z",
  "sources": [
    { "name": "nvd", "display_name": "NVD", "last_sync_at": "...",
      "last_sync_status": "success", "is_enabled": true }
  ],
  "range_from": null, "range_to": null
}
```

`kev_count` (distinct CVEs in the KEV feed) and
`high_epss_count` (latest EPSS ≥ 0.7) are range-independent.
Errors: **401**, **422** (bad date).

### `GET /api/v1/dashboard/trends`

Same `from` / `to` params; defaults to the last 30 days when no
range is given. Response:

```json
{
  "range_from": "2026-10-19", "range_to": "2026-11-18",
  "publications_per_day": [{ "date": "2026-11-17", "count": 2 }],
  "severity_distribution": { "CRITICAL": 3, "HIGH": 18 },
  "cwe_distribution": [{ "cwe_id": "CWE-79", "name": "Cross-site Scripting", "count": 5 }],
  "kev_additions_per_day": [{ "date": "2026-11-17", "count": 1 }],
  "epss_buckets": { "0.0-0.1": 30, "0.1-0.5": 12, "0.5-0.9": 5, "0.9-1.0": 3 }
}
```

Errors: **401**, **422**.

## 6. Vulnerabilities — `/api/v1/vulnerabilities` (auth required)

### `GET /api/v1/vulnerabilities`

Search + filter + sort + paginate. Query params:

| Param | Type | Notes |
|---|---|---|
| `q` | string | Matches CVE ID, title or description (case-insensitive) |
| `severity` | repeatable string | e.g. `?severity=CRITICAL&severity=HIGH` |
| `cwe` | string | e.g. `CWE-79` |
| `min_cvss` / `max_cvss` | 0.0–10.0 | |
| `min_epss` / `max_epss` | 0.0–1.0 | |
| `vendor` / `product` | string | Affected-product filter |
| `kev_only` | bool | Default `false` |
| `published_from` / `published_to` | `YYYY-MM-DD` | |
| `sort` | string | `newest` (default) \| `oldest` \| `severity` \| `cvss` \| `epss` \| `risk` |
| `page` / `per_page` | int | Default 1 / 20, `per_page` max 100 |

Response (page object):

```json
{
  "items": [
    { "cve_id": "CVE-2024-12345", "title": "...", "severity": "HIGH",
      "cvss_score": 8.1, "cvss_version": "3.1",
      "epss_score": 0.42, "epss_percentile": 0.91,
      "is_kev": true, "cwe_ids": ["CWE-79"],
      "published_at": "2024-01-15T00:00:00Z" }
  ],
  "total": 50, "page": 1, "per_page": 20, "pages": 3
}
```

Errors: **401**, **422** (unknown `sort`, out-of-range filter).

### `GET /api/v1/vulnerabilities/{cve_id}`

Full detail for one CVE (ID is upper-cased server-side, so
`cve-2024-12345` works). Response:

```json
{
  "cve_id": "CVE-2024-12345", "title": "...", "description": "...",
  "cvss_score": 8.1, "cvss_version": "3.1",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/...",
  "severity": "HIGH",
  "published_at": "...", "last_modified_at": "...",
  "source": "nvd", "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
  "cwes": [{ "cwe_id": "CWE-79", "name": "Cross-site Scripting", "description": "..." }],
  "affected_products": [{ "vendor": "acme", "product": "widget",
    "version_start": "1.0", "version_end": "2.0", "version_range_text": "1.0 – 2.0" }],
  "references": [{ "url": "https://...", "source": "NVD" }],
  "epss": { "epss_score": 0.42, "percentile": 0.91, "model_date": "2026-11-17" },
  "kev": { "vendor_project": "Acme", "product": "Widget",
    "vulnerability_name": "...", "date_added": "2024-02-01",
    "due_date": "2024-02-22", "short_description": "...",
    "required_action": "...", "ransomware_use": "Known" },
  "related": [{ "cve_id": "CVE-2024-99999", "title": "...",
    "severity": "MEDIUM", "cvss_score": 5.4, "published_at": "..." }],
  "remediation": "..."
}
```

`epss` and `kev` are `null` when the CVE has no EPSS score /
is not in KEV. Errors: **401**, **404** (`unknown CVE: ...`).

### `GET /api/v1/vulnerabilities/{cve_id}/related`

CVEs sharing a CWE with `cve_id` (up to 5), as a bare JSON array
of `{cve_id, title, severity, cvss_score, published_at}`.
Errors: **401**, **404**.

## 7. Intelligence — `/api/v1/intelligence` (auth required)

### `GET /api/v1/intelligence/kev`

Newest CISA KEV additions first. `page` / `per_page` (default
1 / 20, max 100). Response is a page object; each item:

```json
{ "cve_id": "CVE-2024-12345", "vendor_project": "Acme",
  "product": "Widget", "vulnerability_name": "...",
  "date_added": "2024-02-01", "due_date": "2024-02-22",
  "short_description": "...", "required_action": "...",
  "ransomware_use": "Known", "is_indexed": true }
```

`is_indexed` is true when the CVE is also in the local
`vulnerabilities` table. Errors: **401**, **422**.

### `GET /api/v1/intelligence/epss-ranking`

Top CVEs by latest EPSS score, descending. Same pagination.
Item: `{cve_id, title, severity, cvss_score, epss_score,
percentile, model_date}`. Errors: **401**, **422**.

### `GET /api/v1/intelligence/timeline`

Recent events merged: newest CVEs, KEV additions, ingestion jobs.
Query: `limit` (default 50, max 50). Response:

```json
{ "events": [
  { "type": "kev", "date": "2026-11-17T00:00:00Z",
    "label": "CVE-2024-12345 added to CISA KEV",
    "cve_id": "CVE-2024-12345", "source": "cisa-kev", "status": null }
] }
```

`type` is `cve` | `kev` | `ingestion`. Errors: **401**, **422**.

### `GET /api/v1/intelligence/metrics-explained`

Static plain-language explainer (no DB access): CVSS vs EPSS vs
KEV, what each measures, what high means, what it does **not**
mean, and limitations. Response:
`{ "note": "...", "metrics": [{ "name": "CVSS", "what_it_measures": "...", "scale": "...", "what_high_means": "...", "what_it_does_not_mean": "...", "limitations": ["..."] }] }`.
Errors: **401**.

## 8. Graph — `/api/v1/graph` (auth required)

Graph nodes are **public intelligence only** — no private
research data (collections, notes) ever appears in a graph
response (verified in Phase 9, `test_graph_node_exposes_no_private_data`).
Node ids are prefixed keys: `vulnerability:<uuid>`,
`cwe:<uuid>`, `attack_technique:<uuid>`,
`product:<vendor>::<product>`, `vendor:<vendor>`.
Node types: `vulnerability` | `cwe` | `attack_technique` |
`product` | `vendor`.

### `GET /api/v1/graph`

Graph centred on one CVE. Query: `seed_cve` (required, 1–32
chars), `depth` (1–2, default 1), `limit` (1–200 nodes, default
50). Response:

```json
{
  "seed": "CVE-2024-12345",
  "nodes": [{ "id": "vulnerability:<uuid>", "type": "vulnerability",
    "label": "CVE-2024-12345", "subtitle": "HIGH · CVSS 8.1",
    "detail_url": "/vulnerabilities/CVE-2024-12345" }],
  "edges": [{ "id": "...", "from": "vulnerability:<uuid>",
    "to": "cwe:<uuid>", "relationship": "HAS_WEAKNESS",
    "source": "nvd", "confidence": "verified" }],
  "has_more": false, "total_nodes": 7, "total_edges": 6, "note": null
}
```

Edges carry `source` and `confidence` (`verified` | `inferred`).
When more nodes were discovered than returned, `has_more` is
true and `total_nodes` / `total_edges` count everything
discovered before the cap. Errors: **401**, **404** (unknown CVE),
**422** (missing `seed_cve`, `depth` out of range).

### `GET /api/v1/graph/search`

Search entities by label/ID across CVE, CWE, technique, product.
Query: `q` (required, 1–128 chars), `limit` (1–50, default 20).
Response: `{ "query": "...", "results": [{ "id": "...",
"type": "cwe", "label": "CWE-79", "subtitle": "..." }] }`.
Errors: **401**, **422**.

### `GET /api/v1/graph/cwe/{cwe_id}/techniques`

Techniques linked to a CWE via stored relationships. An **empty
list is a valid answer** (no stored link), not an error.
Response: `{ "cwe_id": "CWE-79", "techniques": [{
"id": "...", "technique_id": "T1059.001", "name": "...",
"tactic": "Execution", "relationship": "...", "source": "...",
"confidence": "..." }] }`. Errors: **401**, **404** (unknown CWE).

### `GET /api/v1/graph/node/{node_type}/{node_id}`

Full record fields for one entity plus its direct neighbours.
Response: `{ "id": "...", "type": "cwe", "label": "CWE-79",
"subtitle": "...", "detail_url": "...", "fields": { ... },
"neighbours": [ ... ], "neighbour_edges": [ ... ] }`.
Errors: **401**, **404** (unknown node type or unknown node).

### `POST /api/v1/graph/expand`

Neighbours of one node (progressive graph expansion). Body:
`{ "node_type": "cwe", "node_id": "cwe:<uuid>" }`.
Response: `{ "node_id": "...", "node_type": "cwe", "nodes": [...],
"edges": [...], "has_more": false, "total_nodes": N,
"total_edges": N }`. Errors: **401**, **404**, **422**
(bad `node_type`).

## 9. AI — `/api/v1/ai`

All AI endpoints require auth **except** `GET /ai/status`.
Conversations and analyses are owner-isolated: another user's
object returns **404**, never 403. CSRF Origin check applies to
the whole router (§1).

### `GET /api/v1/ai/status` — no auth

```json
{ "provider_configured": false, "provider": null, "mode": "fallback" }
```

`mode` is `"provider"` or `"fallback"`. Never exposes keys or
key presence beyond the boolean.

### `POST /api/v1/ai/analyze` — auth required, 200

Body: `{ "cve_id": "CVE-2024-12345", "analysis_type": "simple" }`.
`analysis_type` is one of `simple`, `advanced`, `impact`,
`affected_systems`, `root_cause`, `attack_scenarios`,
`verification`, `remediation`, `prevention`, `assessment`
(default `simple`). Returns the exact 10-section analysis:

```json
{
  "cve_id": "CVE-2024-12345", "analysis_type": "simple",
  "ai_mode": "fallback", "model": null, "fallback_reason": null,
  "analysis": {
    "executive_summary": "...", "technical_explanation": "...",
    "root_cause": "...", "potential_impact": "...",
    "affected_components": "...", "risk_assessment": "...",
    "defensive_verification": "...", "remediation": "...",
    "references": [{ "label": "...", "url": "https://..." }],
    "confidence_and_limitations": {
      "confidence": "low",
      "limitations": ["rule-based summary — no AI provider configured"]
    }
  },
  "citations": [{ "cve_id": "CVE-2024-12345", "source": "nvd", "url": "..." }]
}
```

`ai_mode` is `"provider"` or `"fallback"`; in fallback mode the
same 10 sections are assembled rule-based from the DB record, and
a section with no data says "Not available in the indexed record"
— missing data is never reported as 0. When a user is provided,
the analysis is saved to `saved_analyses`. Errors: **401**,
**404** (unknown CVE), **422** (bad `analysis_type`), **429**
(more than 10 analyses per user per hour — counted from
`saved_analyses` rows, so opening a new conversation does not
reset it).

### `POST /api/v1/ai/chat` — auth required, 200

Body: `{ "question": "What is CVE-2024-12345?", "conversation_id": "<uuid>" }`
— `conversation_id` is optional; without it a new conversation
is created and auto-titled from the first question (first 60
chars). `question` is 1–2000 chars. The assistant detects CVE IDs
in the question and fetches those records first; otherwise it
RAG-retrieves the top 5. Response:

```json
{ "answer": "...", "citations": [{ "cve_id": "...", "source": "nvd", "url": "..." }],
  "conversation_id": "<uuid>", "ai_mode": "fallback", "model": null }
```

If retrieval returns nothing, the answer says plainly that no
indexed records matched. Errors: **401**, **404** (conversation
belongs to another user), **422** (empty / too-long question).

### `GET /api/v1/ai/conversations` — auth required

The caller's conversations, newest first. `skip` / `limit`
(default 0 / 20, max 100). Bare JSON array of
`{id, title, created_at, updated_at, message_count}`.
Errors: **401**, **422**.

### `GET /api/v1/ai/conversations/{conversation_id}` — auth required

One conversation with its messages (oldest first). Each message:
`{id, role ("user" | "assistant"), content, citations, created_at}`.
Errors: **401**, **404** (missing, malformed UUID, or another
user's conversation).

### `DELETE /api/v1/ai/conversations/{conversation_id}` — auth required, 204

Deletes the conversation (messages cascade). Empty body on
success. Errors: **401**, **404**.

## 10. Ingestion — `/api/v1/ingestion`

`GET /status` and `GET /jobs` require any logged-in user;
`POST /sync/{source}` is **admin-only**. CSRF Origin check
applies to the whole router.

### `GET /api/v1/ingestion/status` — auth required

Sync status per source, with the latest job's counts. Bare JSON
array:

```json
[{ "source": "nvd", "display_name": "NVD", "is_enabled": true,
   "last_sync_at": "2026-11-17T10:00:00Z", "last_sync_status": "success",
   "last_job": { "id": "<uuid>", "source": "nvd",
     "started_at": "...", "finished_at": "...", "status": "success",
     "records_fetched": 50, "records_created": 50,
     "records_updated": 0, "records_skipped": 0,
     "error_message": null, "triggered_by": "admin:professor" } }]
```

`last_job` is `null` when a source has never run. Errors: **401**.

### `GET /api/v1/ingestion/jobs` — auth required

Paginated job history, newest first. `skip` / `limit` (default
0 / 20, max 100); optional `source` filter (`nvd`, `cisa-kev`,
`epss`, `mitre-attack`, `mitre-cwe`). Bare JSON array of
`IngestionJobResponse` objects (same shape as `last_job` above).
Errors: **401**, **404** (unknown `source` filter), **422**.

### `POST /api/v1/ingestion/sync/{source}` — admin only, 200

Triggers a bounded sync run. `source` is one of `nvd`, `kev`,
`epss`, `mitre`, `mitre-attack`, `mitre-cwe` (`mitre` = both
MITRE catalogs). Query: `days` (1–120, default 7 — NVD runs
incrementally over the last `days` days), `limit` (optional cap),
`full` (default `false`; even with `full=true` the run stays
bounded by the `days` window — an unbounded full re-ingestion is
never allowed through this endpoint).

Response:

```json
{ "source": "nvd", "job_id": "<uuid>", "status": "success",
  "records_fetched": 50, "records_created": 12,
  "records_updated": 3, "records_skipped": 35, "error_message": null }
```

Errors: **401**, **403** (not admin), **404** (unknown source —
`bogus`, `NVD`, `nvd;rm` and `evil-feed` are all 404; the
endpoint takes a source **name** from an allow-list, never a URL,
so there is no SSRF surface), **429** (a run for the same source
is already running, or one finished less than 5 minutes ago).

## 11. Research — `/api/v1/research` (auth required, owner-only)

Every query filters by the caller's `user_id`; every single-object
access returns **404** for another user's data. CSRF Origin check
applies to the whole router. All list endpoints use `skip` /
`limit` (default 0 / 50, max 100) and return
`{"items": [...], "total": N, "skip": N, "limit": N}`.

### Collections

- `POST /research/collections` — body `{ "name": "...",
  "description": "...", "is_public": false }` (`name` 1–128
  chars). **201**. Returns
  `{id, name, description, is_public, item_count, created_at,
  updated_at}`.
- `GET /research/collections` — the caller's collections, newest
  first.
- `GET /research/collections/{collection_id}` — one collection.
  **404** if missing or another user's.
- `PATCH /research/collections/{collection_id}` — body with any of
  `name`, `description`, `is_public`. Returns the updated
  collection.
- `DELETE /research/collections/{collection_id}` — **204**, empty
  body. Items cascade.
- `GET /research/collections/{collection_id}/status` — investigation
  status. There is **no status column** on collections (Phase 8
  could not modify models): status is tracked via a note linked
  to the collection whose tags contain `"status"` and whose title
  holds the status value (e.g. `"investigating"`). Response:
  `{ "collection_id": "<uuid>", "status": "investigating",
  "note_id": "<uuid>", "note_title": "investigating" }`.
  With no such note, `status` is `"not_started"` and `note_id` /
  `note_title` are `null`.

### Collection items

- `POST /research/collections/{collection_id}/items` — body
  `{ "item_type": "vulnerability" | "cwe" | "attack_technique",
  "item_id": "<uuid>" }`. **201** for a new item, **200** with the
  existing item for an idempotent duplicate. Returns
  `{id, collection_id, item_type, item_id, label, name, added_at}`.
- `GET /research/collections/{collection_id}/items` — paginated.
- `DELETE /research/collections/{collection_id}/items/{item_id}?item_type=vulnerability`
  — **204**. `item_type` is a required query param.
- `GET /research/collections/{collection_id}/export?format=json`
  — downloads the collection. `format` is `json` (default) or
  `csv`; anything else is **422**. Returns a file download
  (`Content-Disposition: attachment; filename="collection-<id>.json"`).

### Bookmarks

Bookmarks are a per-user collection named `"Bookmarks"`,
auto-created on first use.

- `POST /research/bookmarks` — body `{item_type, item_id}`.
  **200** (returns the item).
- `GET /research/bookmarks` — paginated; empty list (not 404)
  when the user has no bookmarks yet.
- `DELETE /research/bookmarks/{item_type}/{item_id}` — **204**.

### Notes

- `POST /research/notes` — body `{ "title": "...", "body": "...",
  "tags": ["..."], "collection_id": "<uuid>" | null,
  "vulnerability_id": "<uuid>" | null }`. `body` is required
  (≥ 1 char). **201**. Linked collection / vulnerability must
  belong to the caller (or exist, for vulnerabilities), else
  **404**. Returns `{id, collection_id, vulnerability_id, title,
  body, tags, created_at, updated_at}`.
- `GET /research/notes` — filters: `collection_id`,
  `vulnerability_id`, `tag`. Paginated.
- `GET /research/notes/{note_id}` — one note. **404** if missing
  or another user's.
- `PATCH /research/notes/{note_id}` — any of `title`, `body`,
  `tags`, `collection_id`, `vulnerability_id`.
- `DELETE /research/notes/{note_id}` — **204**.

### Saved analyses

Analyses are written by `POST /ai/analyze` and read here.

- `GET /research/analyses` — filters: `vulnerability_id`,
  `analysis_type`. Paginated. Item:
  `{id, vulnerability_id, cve_id, analysis_type, content,
  ai_mode, model, created_at}`. `content` is the 10-section
  analysis object (see §9).
- `GET /research/analyses/{analysis_id}` — one analysis.
  **404** if missing or another user's.
- `DELETE /research/analyses/{analysis_id}` — **204**.

### Compare

- `POST /research/compare` — body `{ "cve_ids": ["CVE-2024-1",
  "CVE-2024-2"] }` (2–5 CVEs). No persistence. Response:

```json
{ "comparisons": [
  { "cve_id": "CVE-2024-12345", "cvss_score": 8.1, "severity": "HIGH",
    "cwe_ids": ["CWE-79"], "epss_score": 0.42, "epss_percentile": 0.91,
    "kev_listed": true, "published_at": "2024-01-15T00:00:00Z" }
] }
```

A missing number is the string `"unavailable"`, never 0.
Errors: **401**, **422** (fewer than 2 or more than 5 CVEs).

## 12. Learning — `/api/v1/learning` (auth required)

Educational content written for this project (9 topics). The
`related_real_records` in a topic detail are real vulnerability
rows from the database, clearly labelled and separate from the
educational text.

### `GET /api/v1/learning/topics`

Bare object: `{ "topics": [{ "slug": "owasp_top_10",
"title": "OWASP Top 10" }, ...] }` (9 topics). Errors: **401**.

### `GET /api/v1/learning/topics/{slug}`

The topic (sections, content) plus
`"related_real_records": [...]` — real CVE rows related to the
topic's CWE ids. Errors: **401**, **404** (unknown slug).

## 13. Curl examples — the full walk

Base URL `http://localhost:8000`. Cookie jar keeps the session.

```bash
# 1. Register
curl -s -c cookies.txt -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"professor","email":"prof@example.com","password":"correct-horse-battery"}'

# 2. Login (sets the session cookie; use -c/-b to keep it)
curl -s -c cookies.txt -b cookies.txt -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"professor","password":"correct-horse-battery"}'

# 3. Dashboard summary
curl -s -b cookies.txt http://localhost:8000/api/v1/dashboard/summary

# 4. Vulnerability search (critical CVEs, newest first, page 1)
curl -s -b cookies.txt \
  'http://localhost:8000/api/v1/vulnerabilities?severity=CRITICAL&sort=newest&page=1&per_page=20'

# 5. AI analyze (non-AI fallback when no provider is configured)
curl -s -b cookies.txt -X POST http://localhost:8000/api/v1/ai/analyze \
  -H 'Content-Type: application/json' \
  -d '{"cve_id":"CVE-2024-12345","analysis_type":"simple"}'

# 6. Create a collection
curl -s -b cookies.txt -X POST http://localhost:8000/api/v1/research/collections \
  -H 'Content-Type: application/json' \
  -d '{"name":"Web Application Security Research","description":"XSS and injection CVEs"}'
```

> The same walk was run live against the dev database in Phase 9
> as a 23-step end-to-end smoke test (register → dashboard → CVE →
> graph → AI → collection → logout → isolation 404) — 23/23 steps
> as expected. See `docs/TESTING.md` §5 and `docs/SECURITY.md` §5.

## 14. What is NOT in this API

- No bearer-token / API-key authentication (session cookie only).
- No `PUT` endpoints; updates are `PATCH`.
- No bulk import, no webhooks, no streaming (chat is a single
  request/response; no SSE).
- No admin user-management endpoints beyond `/auth/admin/ping`
  (role assignment is done in the database / a future phase).
- No endpoint accepts a URL from the caller (no SSRF surface).
- `/docs`, `/redoc` and `/openapi.json` are public by design —
  see `docs/SECURITY.md` residual risk R4 before any public
  deployment.
