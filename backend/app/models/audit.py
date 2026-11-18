"""Audit logs — DATABASE.md §2.21. Append-only; never deleted by the app."""

import uuid

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Uuid,
)
from sqlalchemy.orm import relationship

from app.models.base import Base, utcnow
from app.models.types import INET, JSONB


class AuditLog(Base):
    """§2.21 — ``details`` never contains secrets or passwords."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("audit_user_created", "user_id", "created_at"),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(
        Uuid,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    action = Column(String(64), nullable=False)
    entity_type = Column(String(64), nullable=True)
    entity_id = Column(Uuid, nullable=True)
    details = Column(JSONB, nullable=True)
    ip_address = Column(INET, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    user = relationship("User")
