"""Conversations — DATABASE.md §2.18–2.19 (AI research assistant, Phase 6)."""

import uuid

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import relationship

from app.models.base import Base, TimestampMixin, utcnow
from app.models.types import JSONB


class Conversation(Base, TimestampMixin):
    """§2.18 — one assistant chat thread, owned by a user."""

    __tablename__ = "conversations"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(
        Uuid,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    title = Column(String(255), nullable=True)

    user = relationship("User", back_populates="conversations")
    messages = relationship(
        "ConversationMessage",
        back_populates="conversation",
        cascade="all, delete-orphan",
    )


class ConversationMessage(Base):
    """§2.19 — one turn in a conversation, with citations."""

    __tablename__ = "conversation_messages"
    __table_args__ = (
        Index(
            "messages_conversation_created", "conversation_id", "created_at"
        ),
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    conversation_id = Column(
        Uuid,
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
    )
    role = Column(String(16), nullable=False)
    content = Column(Text, nullable=False)
    citations = Column(JSONB, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    conversation = relationship("Conversation", back_populates="messages")
