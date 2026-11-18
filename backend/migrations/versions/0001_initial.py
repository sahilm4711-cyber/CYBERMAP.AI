"""Initial migration — all 21 tables (DATABASE.md §2) + seed data.

- Creates the pgvector extension ONLY on PostgreSQL.
- On SQLite the ``embeddings.embedding`` column is JSON (see
  ``app.models.types.EmbeddingVector``); on PostgreSQL it is
  ``vector(1536)``.
- Seeds the 3 roles and the 5 data_sources rows (DATABASE.md §3).
- Downgrade drops all tables (seed rows go with them).

Revision ID: 0001
Revises:
Create Date: 2026-11-17
"""

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

from app.models.sources import DATA_SOURCES  # noqa: E402
from app.models.types import JSONB, INET, EmbeddingVector  # noqa: E402

ROLE_DESCRIPTIONS = {
    "user": "Standard researcher — owns their own research data.",
    "researcher": "Researcher — same access as user; reserved for "
    "future research features.",
    "admin": "Administrator — manages ingestion and users.",
}


def _seed(bind) -> None:
    """Insert the 3 roles + 5 data_sources rows if not already present."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    roles = sa.table(
        "roles",
        sa.column("id", sa.Uuid),
        sa.column("name", sa.String(32)),
        sa.column("description", sa.Text),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    for name, description in ROLE_DESCRIPTIONS.items():
        exists = bind.execute(
            sa.select(sa.literal(1)).select_from(roles).where(
                roles.c.name == name
            )
        ).first()
        if exists is None:
            bind.execute(
                roles.insert().values(
                    id=uuid.uuid4(),
                    name=name,
                    description=description,
                    created_at=now,
                )
            )

    sources = sa.table(
        "data_sources",
        sa.column("id", sa.Uuid),
        sa.column("name", sa.String(64)),
        sa.column("display_name", sa.String(128)),
        sa.column("base_url", sa.Text),
        sa.column("is_enabled", sa.Boolean),
    )
    for name, display_name, base_url in DATA_SOURCES:
        exists = bind.execute(
            sa.select(sa.literal(1)).select_from(sources).where(
                sources.c.name == name
            )
        ).first()
        if exists is None:
            bind.execute(
                sources.insert().values(
                    id=uuid.uuid4(),
                    name=name,
                    display_name=display_name,
                    base_url=base_url,
                    is_enabled=True,
                )
            )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # pgvector extension — Postgres only (DATABASE.md §3).
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # --- §2.1 roles ---
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    # --- §2.2 users ---
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=False)
    op.create_index("ix_users_username", "users", ["username"], unique=False)

    # --- §2.3 user_sessions ---
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("session_token_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_address", INET, nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_token_hash"),
    )
    op.create_index(
        "user_sessions_user_id", "user_sessions", ["user_id"], unique=False
    )

    # --- §2.4 vulnerabilities ---
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cvss_score", sa.Numeric(3, 1), nullable=True),
        sa.Column("cvss_version", sa.String(length=8), nullable=True),
        sa.Column("cvss_vector", sa.String(length=255), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"], unique=False)
    op.create_index("vuln_severity", "vulnerabilities", ["severity"], unique=False)
    op.create_index("vuln_published_at", "vulnerabilities", ["published_at"], unique=False)
    op.create_index("vuln_cvss_score", "vulnerabilities", ["cvss_score"], unique=False)

    # --- §2.5 vulnerability_references ---
    op.create_table(
        "vulnerability_references",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=True),
        sa.Column("tags", JSONB, nullable=True),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"], ["vulnerabilities.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "vulnerability_id", "url", name="uq_vuln_ref_vuln_url"
        ),
    )
    op.create_index(
        "vuln_ref_vuln_id", "vulnerability_references", ["vulnerability_id"],
        unique=False,
    )

    # --- §2.6 affected_products ---
    op.create_table(
        "affected_products",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("version_start", sa.String(length=64), nullable=True),
        sa.Column("version_end", sa.String(length=64), nullable=True),
        sa.Column("version_range_text", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"], ["vulnerabilities.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "affected_product_vendor_product", "affected_products",
        ["vendor", "product"], unique=False,
    )

    # --- §2.7 cwe_entries ---
    op.create_table(
        "cwe_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cwe_id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("extended_description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cwe_id"),
    )

    # --- §2.8 attack_techniques ---
    op.create_table(
        "attack_techniques",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("technique_id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("tactic", sa.String(length=64), nullable=True),
        sa.Column("platforms", JSONB, nullable=True),
        sa.Column("detection", sa.Text(), nullable=True),
        sa.Column("mitigations", JSONB, nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("technique_id"),
    )

    # --- §2.9 vulnerability_relationships ---
    op.create_table(
        "vulnerability_relationships",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("from_type", sa.String(length=32), nullable=False),
        sa.Column("from_id", sa.Uuid(), nullable=False),
        sa.Column("to_type", sa.String(length=32), nullable=False),
        sa.Column("to_id", sa.Uuid(), nullable=False),
        sa.Column("relationship", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("confidence", sa.String(length=16), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "from_type", "from_id", "to_type", "to_id", "relationship",
            name="uq_vuln_rel_edge",
        ),
    )
    op.create_index(
        "vuln_rel_from", "vulnerability_relationships",
        ["from_type", "from_id"], unique=False,
    )
    op.create_index(
        "vuln_rel_to", "vulnerability_relationships",
        ["to_type", "to_id"], unique=False,
    )

    # --- §2.10 kev_entries ---
    op.create_table(
        "kev_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=True),
        sa.Column("vendor_project", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("vulnerability_name", sa.String(length=255), nullable=True),
        sa.Column("date_added", sa.Date(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("short_description", sa.Text(), nullable=True),
        sa.Column("required_action", sa.Text(), nullable=True),
        sa.Column("ransomware_use", sa.String(length=32), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"], ["vulnerabilities.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
    )
    op.create_index("kev_date_added", "kev_entries", ["date_added"], unique=False)
    op.create_index("kev_due_date", "kev_entries", ["due_date"], unique=False)

    # --- §2.11 epss_scores ---
    op.create_table(
        "epss_scores",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=True),
        sa.Column("epss_score", sa.Numeric(6, 5), nullable=False),
        sa.Column("percentile", sa.Numeric(6, 5), nullable=False),
        sa.Column("model_date", sa.Date(), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"], ["vulnerabilities.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "cve_id", "model_date", name="uq_epss_cve_model_date"
        ),
    )
    op.create_index("epss_score_idx", "epss_scores", ["epss_score"], unique=False)

    # --- §2.12 data_sources ---
    op.create_table(
        "data_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=True),
        sa.Column("base_url", sa.Text(), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_status", sa.String(length=32), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    # --- §2.13 ingestion_jobs ---
    op.create_table(
        "ingestion_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("records_fetched", sa.Integer(), nullable=False),
        sa.Column("records_created", sa.Integer(), nullable=False),
        sa.Column("records_updated", sa.Integer(), nullable=False),
        sa.Column("records_skipped", sa.Integer(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("triggered_by", sa.String(length=32), nullable=True),
        sa.Column("details", JSONB, nullable=True),
        sa.ForeignKeyConstraint(
            ["source_id"], ["data_sources.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ingestion_jobs_source_started", "ingestion_jobs",
        ["source_id", "started_at"], unique=False,
    )

    # --- §2.14 research_collections ---
    op.create_table(
        "research_collections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_public", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "collections_user_id", "research_collections", ["user_id"],
        unique=False,
    )

    # --- §2.15 collection_items ---
    op.create_table(
        "collection_items",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("collection_id", sa.Uuid(), nullable=False),
        sa.Column("item_type", sa.String(length=32), nullable=False),
        sa.Column("item_id", sa.Uuid(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["collection_id"], ["research_collections.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "collection_id", "item_type", "item_id", name="uq_collection_item"
        ),
    )

    # --- §2.16 research_notes ---
    op.create_table(
        "research_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("collection_id", sa.Uuid(), nullable=True),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("tags", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["collection_id"], ["research_collections.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"], ["vulnerabilities.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("notes_user_id", "research_notes", ["user_id"], unique=False)
    op.create_index(
        "notes_vulnerability_id", "research_notes", ["vulnerability_id"],
        unique=False,
    )

    # --- §2.17 saved_analyses ---
    op.create_table(
        "saved_analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("analysis_type", sa.String(length=64), nullable=False),
        sa.Column("content", JSONB, nullable=False),
        sa.Column("ai_mode", sa.String(length=16), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"], ["vulnerabilities.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # --- §2.18 conversations ---
    op.create_table(
        "conversations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # --- §2.19 conversation_messages ---
    op.create_table(
        "conversation_messages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("conversation_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("citations", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["conversation_id"], ["conversations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "messages_conversation_created", "conversation_messages",
        ["conversation_id", "created_at"], unique=False,
    )

    # --- §2.20 embeddings ---
    op.create_table(
        "embeddings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("chunk_text", sa.Text(), nullable=False),
        sa.Column("embedding", EmbeddingVector, nullable=True),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "entity_type", "entity_id", "model",
            name="uq_embedding_entity_model",
        ),
    )
    # NOTE: the pgvector HNSW index (vector_cosine_ops) is only valid
    # on PostgreSQL and only after real vectors exist; Phase 6 adds it
    # in a later migration. SQLite stores JSON and skips it.

    # --- §2.21 audit_logs ---
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=True),
        sa.Column("entity_id", sa.Uuid(), nullable=True),
        sa.Column("details", JSONB, nullable=True),
        sa.Column("ip_address", INET, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "audit_user_created", "audit_logs", ["user_id", "created_at"],
        unique=False,
    )

    _seed(bind)


def downgrade() -> None:
    # Reverse creation order (children first).
    for table in [
        "audit_logs",
        "embeddings",
        "conversation_messages",
        "conversations",
        "saved_analyses",
        "research_notes",
        "collection_items",
        "research_collections",
        "ingestion_jobs",
        "data_sources",
        "epss_scores",
        "kev_entries",
        "vulnerability_relationships",
        "attack_techniques",
        "cwe_entries",
        "affected_products",
        "vulnerability_references",
        "vulnerabilities",
        "user_sessions",
        "users",
        "roles",
    ]:
        op.drop_table(table)
