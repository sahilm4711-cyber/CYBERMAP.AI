"""Migration tests (Phase 3).

Runs the real Alembic migration against a fresh temp SQLite file:
upgrade head -> downgrade base -> upgrade head again. Asserts all 21
tables exist, the seed rows are present, and the downgrade removes
the tables. PostgreSQL/pgvector behaviour cannot be verified here
(no Postgres in this environment) — the migration creates the
extension only when the dialect is PostgreSQL.
"""

import os

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

MIGRATIONS_INI = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "migrations",
    "alembic.ini",
)

EXPECTED_TABLES = {
    "roles",
    "users",
    "user_sessions",
    "vulnerabilities",
    "vulnerability_references",
    "affected_products",
    "cwe_entries",
    "attack_techniques",
    "vulnerability_relationships",
    "kev_entries",
    "epss_scores",
    "data_sources",
    "ingestion_jobs",
    "research_collections",
    "collection_items",
    "research_notes",
    "saved_analyses",
    "conversations",
    "conversation_messages",
    "embeddings",
    "audit_logs",
}


def _alembic_config(db_url: str) -> Config:
    cfg = Config(MIGRATIONS_INI)
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def _tables(db_url: str) -> set[str]:
    engine = create_engine(db_url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_migration_upgrade_downgrade_upgrade_cycle(tmp_path):
    db_path = tmp_path / "migration.db"
    db_url = f"sqlite:///{db_path}"
    cfg = _alembic_config(db_url)

    # 1. Upgrade to head.
    command.upgrade(cfg, "head")
    tables = _tables(db_url)
    assert EXPECTED_TABLES.issubset(tables)
    assert "alembic_version" in tables

    engine = create_engine(db_url)
    with engine.connect() as conn:
        roles = [r[0] for r in conn.exec_driver_sql(
            "SELECT name FROM roles ORDER BY name"
        )]
        sources = [r[0] for r in conn.exec_driver_sql(
            "SELECT name FROM data_sources ORDER BY name"
        )]
        version = conn.exec_driver_sql(
            "SELECT version_num FROM alembic_version"
        ).fetchall()
    engine.dispose()
    assert roles == ["admin", "researcher", "user"]
    assert sources == [
        "cisa-kev",
        "epss",
        "mitre-attack",
        "mitre-cwe",
        "nvd",
    ]
    assert version == [("0001",)]

    # 2. Downgrade to base — all app tables gone.
    command.downgrade(cfg, "base")
    assert _tables(db_url) == {"alembic_version"}

    # 3. Upgrade to head again — tables and seeds restored.
    command.upgrade(cfg, "head")
    tables = _tables(db_url)
    assert EXPECTED_TABLES.issubset(tables)
    engine = create_engine(db_url)
    with engine.connect() as conn:
        roles = [r[0] for r in conn.exec_driver_sql(
            "SELECT name FROM roles ORDER BY name"
        )]
    engine.dispose()
    assert roles == ["admin", "researcher", "user"]
