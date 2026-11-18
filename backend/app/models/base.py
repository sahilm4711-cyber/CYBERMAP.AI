"""Shared model base: UUID PKs + UTC timestamps.

All models import ``Base`` from ``app.core.database`` (the single
declarative base Alembic's ``env.py`` reads). Mixins here add the
columns DATABASE.md requires on (almost) every table.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime
from sqlalchemy import Uuid

from app.core.database import Base

__all__ = ["Base", "TimestampMixin", "utcnow"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc_aware(value: datetime | None) -> datetime | None:
    """Return ``value`` as a timezone-aware UTC datetime.

    SQLite stores datetimes without tzinfo, so values read back from
    a SQLite database are naive even though they were written as UTC.
    Treat naive values as UTC instead of crashing on aware/naive
    comparisons.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class TimestampMixin:
    """``created_at`` / ``updated_at`` (UTC), as required by DATABASE.md §1."""

    created_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )


def uuid_pk():
    """UUID primary-key column (DATABASE.md §1)."""
    return Column(Uuid, primary_key=True, default=uuid.uuid4)
