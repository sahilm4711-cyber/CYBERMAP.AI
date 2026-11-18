"""AI service layer — Phase 6.

Thin service wrappers the API router calls: analysis (with rate
limiting and persistence) and assistant chat (with conversation
persistence). Pure AI logic lives in ``app.ai.analyst`` and
``app.ai.chat``; this module owns the DB writes and the exception
types the router translates to HTTP statuses.
"""

from sqlalchemy.orm import Session

from app.ai.analyst import (
    InvalidAnalysisTypeError,
    RateLimitExceededError,
    VulnerabilityNotFoundError,
    analyze_vulnerability as _analyze,
)
from app.ai.chat import answer_question as _answer_question
from app.models import User

__all__ = [
    "InvalidAnalysisTypeError",
    "RateLimitExceededError",
    "VulnerabilityNotFoundError",
    "analyze_vulnerability",
    "answer_question",
]


def analyze_vulnerability(
    db: Session,
    cve_id: str,
    analysis_type: str,
    user: User,
) -> dict:
    """Analyse ``cve_id`` for ``user`` (rate-limited, saved)."""
    return _analyze(db, cve_id, analysis_type, user=user)


def answer_question(
    db: Session,
    user: User,
    conversation_id,
    question: str,
) -> dict:
    """Answer ``question`` for ``user`` in (or starting) a conversation."""
    return _answer_question(db, user, conversation_id, question)
