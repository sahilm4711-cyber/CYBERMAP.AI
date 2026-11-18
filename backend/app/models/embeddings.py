"""Embeddings — DATABASE.md §2.20 (vector store for RAG, Phase 6).

The ``embedding`` column is ``vector(1536)`` on PostgreSQL and JSON
on SQLite (see ``app.models.types.EmbeddingVector``).
"""

import uuid

from sqlalchemy import (
    Column,
    DateTime,
    String,
    Text,
    Uuid,
    UniqueConstraint,
)

from app.models.base import Base, utcnow
from app.models.types import EmbeddingVector


class Embedding(Base):
    """§2.20 — one embedded chunk of an entity's text."""

    __tablename__ = "embeddings"
    __table_args__ = (
        UniqueConstraint(
            "entity_type", "entity_id", "model",
            name="uq_embedding_entity_model",
        ),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    entity_type = Column(String(32), nullable=False)
    entity_id = Column(Uuid, nullable=False)
    chunk_text = Column(Text, nullable=False)
    embedding = Column(EmbeddingVector, nullable=True)
    model = Column(String(128), nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
