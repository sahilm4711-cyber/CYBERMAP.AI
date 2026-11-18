# CyberMap AI — Database Design

> **Status:** Design complete (Phase 1); SQLAlchemy models +
> Alembic migrations implemented in Phase 3 and verified
> (upgrade → downgrade → upgrade on a fresh SQLite file;
> `tests/test_models.py` 19 tests, `tests/test_migrations.py`).
> All 10 phases are now done — see `docs/ROADMAP.md`.
> This document remains the schema contract the models match.

## 1. Principles

- **PostgreSQL 16 + pgvector** in production/Docker. Local development
  without Docker may use SQLite (no vector column there — embeddings
  fall back to a JSON column; see §3).
- **UUID primary keys** for user-facing and cross-referenced tables
  (`users`, `vulnerabilities`, collections, conversations, notes,
  analyses). External identifiers (CVE ID, CWE ID, KEV `cveID`) stay as
  natural unique keys alongside the UUID.
- **Timestamps everywhere:** `created_at`, `updated_at` (UTC).
- **Provenance everywhere:** every ingested record stores `source`
  (e.g. `nvd`, `cisa-kev`, `epss`, `mitre-attack`, `mitre-cwe`),
  `source_url`, `source_updated_at`, and `ingested_at`.
- **Safe upserts:** ingestion matches on the natural key and updates
  only when `source_updated_at` is newer; verified records are never
  overwritten with incomplete data.
- **No duplicated external records:** one row per CVE / CWE / technique.
- **Referential integrity:** foreign keys with `ON DELETE CASCADE` for
  owned data (notes, collection items) and `ON DELETE SET NULL` /
  `RESTRICT` for shared reference data.
- **Soft delete is not used** — research data is deleted by its owner;
  audit logs are append-only and never deleted by the app.

## 2. Tables

### 2.1 `roles`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `name` | VARCHAR(32) UNIQUE | `user`, `researcher`, `admin` |
| `description` | TEXT | |
| `created_at` | TIMESTAMPTZ | |

Seeded with the three roles in the first migration.

### 2.2 `users`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `username` | VARCHAR(64) UNIQUE, NOT NULL | |
| `email` | VARCHAR(255) UNIQUE, NOT NULL | |
| `password_hash` | VARCHAR(255) NOT NULL | Argon2id hash, never plaintext |
| `role_id` | UUID FK → `roles.id`, NOT NULL | |
| `is_active` | BOOLEAN, default true | |
| `created_at` / `updated_at` | TIMESTAMPTZ | |
| `last_login_at` | TIMESTAMPTZ NULL | |

Indexes: `users_email`, `users_username` (unique indexes cover these).

### 2.3 `user_sessions`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `user_id` | UUID FK → `users.id` ON DELETE CASCADE | |
| `session_token_hash` | VARCHAR(255) UNIQUE, NOT NULL | SHA-256 of the cookie token |
| `created_at` | TIMESTAMPTZ | |
| `expires_at` | TIMESTAMPTZ NOT NULL | |
| `revoked_at` | TIMESTAMPTZ NULL | Logout / password change revokes |
| `ip_address` | INET NULL | audit only |
| `user_agent` | TEXT NULL | audit only |

Index: `user_sessions_user_id`.

### 2.4 `vulnerabilities`
Core CVE record. One row per CVE ID.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `cve_id` | VARCHAR(32) UNIQUE, NOT NULL | e.g. `CVE-2024-12345` |
| `title` | TEXT NULL | Short title (derived from description when absent) |
| `description` | TEXT NOT NULL | |
| `cvss_score` | NUMERIC(3,1) NULL | Primary CVSS base score |
| `cvss_version` | VARCHAR(8) NULL | `3.1`, `3.0`, `2.0` |
| `cvss_vector` | VARCHAR(255) NULL | e.g. `CVSS:3.1/AV:N/...` |
| `severity` | VARCHAR(16) NULL | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` |
| `published_at` | TIMESTAMPTZ NULL | |
| `last_modified_at` | TIMESTAMPTZ NULL | |
| `source` | VARCHAR(32) NOT NULL | `nvd` |
| `source_url` | TEXT NULL | |
| `source_updated_at` | TIMESTAMPTZ NULL | NVD `lastModified` |
| `ingested_at` / `created_at` / `updated_at` | TIMESTAMPTZ | |

Indexes: `vuln_cve_id` (unique), `vuln_severity`, `vuln_published_at`,
`vuln_cvss_score`, full-text index on `description` (Postgres `tsvector`).

### 2.5 `vulnerability_references`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `vulnerability_id` | UUID FK → `vulnerabilities.id` ON DELETE CASCADE | |
| `url` | TEXT NOT NULL | |
| `source` | VARCHAR(64) NULL | e.g. vendor name, `NVD` |
| `tags` | JSONB | NVD reference tags |

Unique: (`vulnerability_id`, `url`). Index: `vuln_ref_vuln_id`.

### 2.6 `affected_products`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `vulnerability_id` | UUID FK → `vulnerabilities.id` ON DELETE CASCADE | |
| `vendor` | VARCHAR(255) NULL | |
| `product` | VARCHAR(255) NULL | |
| `version_start` | VARCHAR(64) NULL | `versionStartIncluding/Excluding` |
| `version_end` | VARCHAR(64) NULL | `versionEndIncluding/Excluding` |
| `version_range_text` | TEXT NULL | human-readable range |

Index: `affected_product_vendor_product` on (`vendor`, `product`).

### 2.7 `cwe_entries`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `cwe_id` | VARCHAR(16) UNIQUE, NOT NULL | e.g. `CWE-79` |
| `name` | VARCHAR(255) NOT NULL | |
| `description` | TEXT NULL | |
| `extended_description` | TEXT NULL | |
| `category` | VARCHAR(64) NULL | weakness category |
| `source` | VARCHAR(32) NOT NULL | `mitre-cwe` |
| `source_url` | TEXT NULL | |
| `ingested_at` / `created_at` / `updated_at` | TIMESTAMPTZ | |

### 2.8 `attack_techniques`
MITRE ATT&CK techniques (enterprise).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `technique_id` | VARCHAR(16) UNIQUE, NOT NULL | e.g. `T1059.001` |
| `name` | VARCHAR(255) NOT NULL | |
| `description` | TEXT NULL | |
| `tactic` | VARCHAR(64) NULL | e.g. `Execution` |
| `platforms` | JSONB | e.g. `["Windows", "Linux"]` |
| `detection` | TEXT NULL | |
| `mitigations` | JSONB | mitigation names/ids |
| `source` | VARCHAR(32) NOT NULL | `mitre-attack` |
| `source_url` | TEXT NULL | |
| `ingested_at` / `created_at` / `updated_at` | TIMESTAMPTZ | |

### 2.9 `vulnerability_relationships`
Edges of the knowledge graph. Every edge has a source or is marked
inferred.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `from_type` | VARCHAR(32) NOT NULL | `vulnerability`, `cwe`, `attack_technique`, `product`, `vendor` |
| `from_id` | UUID NOT NULL | (polymorphic — see note) |
| `to_type` | VARCHAR(32) NOT NULL | same enum |
| `to_id` | UUID NOT NULL | |
| `relationship` | VARCHAR(64) NOT NULL | e.g. `HAS_WEAKNESS`, `EXPLOITS`, `AFFECTS`, `MITIGATED_BY` |
| `source` | VARCHAR(32) NOT NULL | `nvd`, `mitre-attack`, `mitre-cwe`, or `inferred` |
| `source_url` | TEXT NULL | |
| `confidence` | VARCHAR(16) NULL | `verified` | `inferred` |
| `created_at` | TIMESTAMPTZ | |

Unique: (`from_type`, `from_id`, `to_type`, `to_id`, `relationship`) —
prevents duplicate connections. Indexes on (`from_type`, `from_id`) and
(`to_type`, `to_id`).

> Polymorphic note: `from_id`/`to_id` reference UUIDs in different
> tables. Referential integrity is enforced in the service layer
> (Phase 7 verifies both endpoints exist before inserting an edge).

### 2.10 `kev_entries`
CISA Known Exploited Vulnerabilities.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `cve_id` | VARCHAR(32) UNIQUE, NOT NULL | |
| `vulnerability_id` | UUID FK → `vulnerabilities.id` NULL | linked when the CVE is indexed |
| `vendor_project` | VARCHAR(255) NULL | |
| `product` | VARCHAR(255) NULL | |
| `vulnerability_name` | VARCHAR(255) NULL | |
| `date_added` | DATE NULL | |
| `due_date` | DATE NULL | remediation due date |
| `short_description` | TEXT NULL | |
| `required_action` | TEXT NULL | |
| `ransomware_use` | VARCHAR(32) NULL | `Known` / `Unknown` |
| `source` | VARCHAR(32) NOT NULL | `cisa-kev` |
| `ingested_at` / `created_at` / `updated_at` | TIMESTAMPTZ | |

Index: `kev_date_added`, `kev_due_date`.

### 2.11 `epss_scores`
FIRST EPSS scores. One row per CVE per model date.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `cve_id` | VARCHAR(32) NOT NULL | |
| `vulnerability_id` | UUID FK → `vulnerabilities.id` NULL | |
| `epss_score` | NUMERIC(6,5) NOT NULL | 0.00000–1.00000 |
| `percentile` | NUMERIC(6,5) NOT NULL | |
| `model_date` | DATE NOT NULL | EPSS model date |
| `ingested_at` | TIMESTAMPTZ | |

Unique: (`cve_id`, `model_date`). Index: `epss_score` (for risk ranking).

### 2.12 `data_sources`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `name` | VARCHAR(64) UNIQUE, NOT NULL | `nvd`, `cisa-kev`, `epss`, `mitre-attack`, `mitre-cwe` |
| `display_name` | VARCHAR(128) | |
| `base_url` | TEXT NULL | |
| `last_sync_at` | TIMESTAMPTZ NULL | |
| `last_sync_status` | VARCHAR(32) NULL | `success`, `partial`, `failed`, `never` |
| `is_enabled` | BOOLEAN, default true | |

### 2.13 `ingestion_jobs`
One row per connector run.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `source_id` | UUID FK → `data_sources.id` | |
| `started_at` | TIMESTAMPTZ NOT NULL | |
| `finished_at` | TIMESTAMPTZ NULL | |
| `status` | VARCHAR(32) NOT NULL | `running`, `success`, `partial`, `failed` |
| `records_fetched` | INTEGER, default 0 | |
| `records_created` | INTEGER, default 0 | |
| `records_updated` | INTEGER, default 0 | |
| `records_skipped` | INTEGER, default 0 | |
| `error_message` | TEXT NULL | |
| `triggered_by` | VARCHAR(32) NULL | `scheduler`, `admin:<username>` |
| `details` | JSONB | per-connector notes |

Index: `ingestion_jobs_source_started` on (`source_id`, `started_at` DESC).

### 2.14 `research_collections`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `user_id` | UUID FK → `users.id` ON DELETE CASCADE | owner |
| `name` | VARCHAR(128) NOT NULL | e.g. "Web Application Security Research" |
| `description` | TEXT NULL | |
| `is_public` | BOOLEAN, default false | |
| `created_at` / `updated_at` | TIMESTAMPTZ | |

Index: `collections_user_id`.

### 2.15 `collection_items`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `collection_id` | UUID FK → `research_collections.id` ON DELETE CASCADE | |
| `item_type` | VARCHAR(32) NOT NULL | `vulnerability`, `cwe`, `attack_technique` |
| `item_id` | UUID NOT NULL | |
| `added_at` | TIMESTAMPTZ | |

Unique: (`collection_id`, `item_type`, `item_id`).

### 2.16 `research_notes`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `user_id` | UUID FK → `users.id` ON DELETE CASCADE | |
| `collection_id` | UUID FK → `research_collections.id` NULL | optional link |
| `vulnerability_id` | UUID FK → `vulnerabilities.id` NULL | optional link |
| `title` | VARCHAR(255) NULL | |
| `body` | TEXT NOT NULL | |
| `tags` | JSONB | |
| `created_at` / `updated_at` | TIMESTAMPTZ | |

Indexes: `notes_user_id`, `notes_vulnerability_id`.

### 2.17 `saved_analyses`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `user_id` | UUID FK → `users.id` ON DELETE CASCADE | |
| `vulnerability_id` | UUID FK → `vulnerabilities.id` ON DELETE CASCADE | |
| `analysis_type` | VARCHAR(64) NOT NULL | `simple`, `advanced`, `impact`, `remediation`, `assessment` |
| `content` | JSONB NOT NULL | structured analysis (see docs/AI_PIPELINE.md) |
| `ai_mode` | VARCHAR(16) NOT NULL | `provider` | `fallback` |
| `model` | VARCHAR(128) NULL | provider model, NULL in fallback |
| `created_at` | TIMESTAMPTZ | |

### 2.18 `conversations`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `user_id` | UUID FK → `users.id` ON DELETE CASCADE | |
| `title` | VARCHAR(255) NULL | auto-derived from first question |
| `created_at` / `updated_at` | TIMESTAMPTZ | |

### 2.19 `conversation_messages`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `conversation_id` | UUID FK → `conversations.id` ON DELETE CASCADE | |
| `role` | VARCHAR(16) NOT NULL | `user`, `assistant` |
| `content` | TEXT NOT NULL | |
| `citations` | JSONB | `[{cve_id, source, url}]` |
| `created_at` | TIMESTAMPTZ | |

Index: `messages_conversation_created` on (`conversation_id`, `created_at`).

### 2.20 `embeddings`
Vector store for RAG.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `entity_type` | VARCHAR(32) NOT NULL | `vulnerability`, `cwe`, `attack_technique` |
| `entity_id` | UUID NOT NULL | |
| `chunk_text` | TEXT NOT NULL | text that was embedded |
| `embedding` | `vector(1536)` on Postgres / JSON on SQLite | |
| `model` | VARCHAR(128) NOT NULL | embedding model name |
| `created_at` | TIMESTAMPTZ | |

Unique: (`entity_type`, `entity_id`, `model`). Index: pgvector HNSW
(`vector_cosine_ops`) on `embedding` when running on Postgres.

> SQLite fallback: the column is stored as JSON and similarity is
> computed in Python (cosine). Correct, but slower — Postgres +
> pgvector is the supported production path.

### 2.21 `audit_logs`
Append-only.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `user_id` | UUID FK → `users.id` NULL | NULL for system events |
| `action` | VARCHAR(64) NOT NULL | e.g. `auth.login`, `ingestion.run`, `admin.user_role_change` |
| `entity_type` | VARCHAR(64) NULL | |
| `entity_id` | UUID NULL | |
| `details` | JSONB NULL | never contains secrets or passwords |
| `ip_address` | INET NULL | |
| `created_at` | TIMESTAMPTZ | |

Index: `audit_user_created` on (`user_id`, `created_at` DESC).

## 3. Migration strategy (Alembic, Phase 3)

- One initial migration creates all tables above.
- `pgvector` extension is created in the migration (`CREATE EXTENSION
  IF NOT EXISTS vector`) — only on Postgres; SQLite dev databases skip
  it (the migration detects the dialect).
- Every later change gets its own migration; no manual `ALTER TABLE`
  outside Alembic.
- Seed: the three roles + the five `data_sources` rows.
