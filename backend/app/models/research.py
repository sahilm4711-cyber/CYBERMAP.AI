"""Research workspace models — DATABASE.md §2.14–2.17.

research_collections, collection_items, research_notes, saved_analyses.
All are owned by a user; isolation is enforced by the ownership helper
in ``app.services.ownership`` (tested in ``tests/test_isolation.py``).
"""

import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    Uuid,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.models.base import Base, TimestampMixin, utcnow
from app.models.types import JSONB


class ResearchCollection(Base, TimestampMixin):
    """§2.14 — a user's collection of research items."""

    __tablename__ = "research_collections"
    __table_args__ = (Index("collections_user_id", "user_id"),)

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(
        Uuid,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    is_public = Column(Boolean, nullable=False, default=False)

    user = relationship("User", back_populates="collections")
    items = relationship(
        "CollectionItem",
        back_populates="collection",
        cascade="all, delete-orphan",
    )
    notes = relationship("ResearchNote", back_populates="collection")


class CollectionItem(Base):
    """§2.15 — one bookmarked entity inside a collection."""

    __tablename__ = "collection_items"
    __table_args__ = (
        UniqueConstraint(
            "collection_id",
            "item_type",
            "item_id",
            name="uq_collection_item",
        ),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    collection_id = Column(
        Uuid,
        ForeignKey("research_collections.id", ondelete="CASCADE"),
        nullable=False,
    )
    item_type = Column(String(32), nullable=False)
    item_id = Column(Uuid, nullable=False)
    added_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    collection = relationship("ResearchCollection", back_populates="items")


class ResearchNote(Base, TimestampMixin):
    """§2.16 — a user's note, optionally linked to a collection/CVE."""

    __tablename__ = "research_notes"
    __table_args__ = (
        Index("notes_user_id", "user_id"),
        Index("notes_vulnerability_id", "vulnerability_id"),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(
        Uuid,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    collection_id = Column(
        Uuid,
        ForeignKey("research_collections.id", ondelete="SET NULL"),
        nullable=True,
    )
    vulnerability_id = Column(
        Uuid,
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
    )
    title = Column(String(255), nullable=True)
    body = Column(Text, nullable=False)
    tags = Column(JSONB, nullable=True)

    user = relationship("User", back_populates="notes")
    collection = relationship(
        "ResearchCollection", back_populates="notes"
    )
    vulnerability = relationship(
        "Vulnerability", back_populates="notes"
    )


class SavedAnalysis(Base):
    """§2.17 — a stored AI/rule-based analysis of one vulnerability."""

    __tablename__ = "saved_analyses"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(
        Uuid,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    vulnerability_id = Column(
        Uuid,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    analysis_type = Column(String(64), nullable=False)
    content = Column(JSONB, nullable=False)
    ai_mode = Column(String(16), nullable=False)
    model = Column(String(128), nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    user = relationship("User", back_populates="saved_analyses")
    vulnerability = relationship(
        "Vulnerability", back_populates="saved_analyses"
    )
