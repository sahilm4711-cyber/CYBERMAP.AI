"""SQLAlchemy models — DATABASE.md §2 (all 21 tables).

Importing this package registers every model on ``Base.metadata``,
which is what Alembic's ``env.py`` and ``create_all`` read.
"""

from app.models.audit import AuditLog
from app.models.auth import (
    ROLE_ADMIN,
    ROLE_RESEARCHER,
    ROLE_USER,
    ROLES,
    Role,
    User,
    UserSession,
)
from app.models.base import Base
from app.models.conversations import Conversation, ConversationMessage
from app.models.embeddings import Embedding
from app.models.research import (
    CollectionItem,
    ResearchCollection,
    ResearchNote,
    SavedAnalysis,
)
from app.models.sources import DATA_SOURCES, DataSource, IngestionJob
from app.models.vulnerabilities import (
    AffectedProduct,
    AttackTechnique,
    CweEntry,
    EpssScore,
    KevEntry,
    Vulnerability,
    VulnerabilityReference,
    VulnerabilityRelationship,
)

__all__ = [
    "Base",
    "AuditLog",
    "Role",
    "User",
    "UserSession",
    "Conversation",
    "ConversationMessage",
    "Embedding",
    "CollectionItem",
    "ResearchCollection",
    "ResearchNote",
    "SavedAnalysis",
    "DataSource",
    "IngestionJob",
    "DATA_SOURCES",
    "AffectedProduct",
    "AttackTechnique",
    "CweEntry",
    "EpssScore",
    "KevEntry",
    "Vulnerability",
    "VulnerabilityReference",
    "VulnerabilityRelationship",
    "ROLE_USER",
    "ROLE_RESEARCHER",
    "ROLE_ADMIN",
    "ROLES",
]
