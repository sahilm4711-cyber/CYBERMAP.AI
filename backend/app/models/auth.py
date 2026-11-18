"""Auth models — DATABASE.md §2.1–2.3: roles, users, user_sessions."""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import relationship

from app.models.base import Base, TimestampMixin, as_utc_aware, utcnow
from app.models.types import INET

ROLE_USER = "user"
ROLE_RESEARCHER = "researcher"
ROLE_ADMIN = "admin"
ROLES = (ROLE_USER, ROLE_RESEARCHER, ROLE_ADMIN)


class Role(Base):
    """§2.1 — seeded with ``user`` / ``researcher`` / ``admin``."""

    __tablename__ = "roles"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    name = Column(String(32), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    users = relationship("User", back_populates="role")


class User(Base, TimestampMixin):
    """§2.2 — ``password_hash`` is an Argon2id hash, never plaintext."""

    __tablename__ = "users"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role_id = Column(
        Uuid, ForeignKey("roles.id"), nullable=False
    )
    is_active = Column(Boolean, nullable=False, default=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    role = relationship("Role", back_populates="users")
    sessions = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )
    collections = relationship(
        "ResearchCollection",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    notes = relationship(
        "ResearchNote", back_populates="user", cascade="all, delete-orphan"
    )
    saved_analyses = relationship(
        "SavedAnalysis", back_populates="user", cascade="all, delete-orphan"
    )
    conversations = relationship(
        "Conversation", back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def role_name(self) -> str | None:
        return self.role.name if self.role else None


class UserSession(Base):
    """§2.3 — only the SHA-256 hash of the cookie token is stored."""

    __tablename__ = "user_sessions"
    __table_args__ = (Index("user_sessions_user_id", "user_id"),)

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(
        Uuid,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    session_token_hash = Column(String(255), unique=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)

    user = relationship("User", back_populates="sessions")

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_expired(self, now: datetime | None = None) -> bool:
        expires_at = as_utc_aware(self.expires_at)
        return (now or utcnow()) >= expires_at
