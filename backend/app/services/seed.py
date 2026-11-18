"""Seed data — the rows DATABASE.md §3 requires in the first migration.

Idempotent: existing rows (matched by natural key) are left alone, so
the function is safe to run from the migration AND from tests/dev
databases built with ``Base.metadata.create_all`` (which never run a
migration).
"""

from sqlalchemy.orm import Session

from app.models import DATA_SOURCES, ROLES, DataSource, Role

ROLE_DESCRIPTIONS = {
    "user": "Standard researcher — owns their own research data.",
    "researcher": "Researcher — same access as user; reserved for "
    "future research features.",
    "admin": "Administrator — manages ingestion and users.",
}


def seed_roles_and_sources(db: Session) -> dict[str, int]:
    """Insert the 3 roles + 5 data_sources if missing. Returns counts."""
    created = {"roles": 0, "data_sources": 0}
    for name in ROLES:
        if db.query(Role).filter(Role.name == name).first() is None:
            db.add(Role(name=name, description=ROLE_DESCRIPTIONS[name]))
            created["roles"] += 1
    for name, display_name, base_url in DATA_SOURCES:
        if (
            db.query(DataSource)
            .filter(DataSource.name == name)
            .first()
            is None
        ):
            db.add(
                DataSource(
                    name=name, display_name=display_name, base_url=base_url
                )
            )
            created["data_sources"] += 1
    db.commit()
    return created


def get_role(db: Session, name: str) -> Role | None:
    """Look up a role by name (used by registration: always ``user``)."""
    return db.query(Role).filter(Role.name == name).first()
