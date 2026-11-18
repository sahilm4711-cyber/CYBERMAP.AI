"""AI API — ``/api/v1/ai`` (Phase 6).

NOTE: this router is intentionally NOT registered in
``app/main.py`` yet — the coordinator registers routers. All
endpoints require auth; conversation access is owner-only and
returns 404 (not 403) for another user's conversation so ownership
cannot be probed. ``/status`` never exposes keys or key presence
beyond a boolean.
"""

import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models import Conversation, ConversationMessage, User
from app.schemas.ai import (
    AIStatusResponse,
    AnalyzeRequest,
    AnalyzeResponse,
    AnalysisSections,
    ChatRequest,
    ChatResponse,
    ConversationDetail,
    ConversationMessageOut,
    ConversationSummary,
)
from app.security.csrf import verify_origin
from app.security.dependencies import get_current_user
from app.services import ai_service
from app.services.ai_service import (
    InvalidAnalysisTypeError,
    RateLimitExceededError,
    VulnerabilityNotFoundError,
)
from app.ai.chat import (
    ConversationNotFoundError,
    InvalidQuestionError,
)

router = APIRouter(
    prefix="/api/v1/ai",
    tags=["ai"],
    dependencies=[Depends(verify_origin)],
)

_PROVIDER_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "groq": "GROQ_API_KEY",
    "google-gemini": "GOOGLE_API_KEY",
    "gemini": "GOOGLE_API_KEY",
    "google": "GOOGLE_API_KEY",
}


@router.get("/status", response_model=AIStatusResponse)
def ai_status() -> AIStatusResponse:
    """Whether an AI provider is configured (never exposes keys)."""
    provider = (settings.ai_provider or "").strip().lower() or None
    key_env = _PROVIDER_KEY_ENV.get(provider or "")
    configured = bool(provider) and bool(
        key_env and os.environ.get(key_env)
    )
    return AIStatusResponse(
        provider_configured=configured,
        provider=provider,
        mode="provider" if configured else "fallback",
    )


@router.post(
    "/analyze", response_model=AnalyzeResponse, status_code=200
)
def analyze(
    payload: AnalyzeRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AnalyzeResponse:
    """Analyse a CVE; returns the 10-section analysis + citations."""
    try:
        result = ai_service.analyze_vulnerability(
            db, payload.cve_id, payload.analysis_type, user
        )
    except VulnerabilityNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except InvalidAnalysisTypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except RateLimitExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
        ) from exc
    return AnalyzeResponse(
        cve_id=result["cve_id"],
        analysis_type=result["analysis_type"],
        ai_mode=result["ai_mode"],
        model=result["model"],
        fallback_reason=result.get("fallback_reason"),
        analysis=AnalysisSections(**result["analysis"]),
        citations=result["citations"],
    )


@router.post("/chat", response_model=ChatResponse, status_code=200)
def chat(
    payload: ChatRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ChatResponse:
    """Ask the research assistant; creates a conversation if needed."""
    try:
        result = ai_service.answer_question(
            db, user, payload.conversation_id, payload.question
        )
    except ConversationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except InvalidQuestionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return ChatResponse(**result)


@router.get(
    "/conversations", response_model=list[ConversationSummary]
)
def list_conversations(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[ConversationSummary]:
    """List the caller's conversations, newest first."""
    rows = (
        db.query(Conversation)
        .filter(Conversation.user_id == user.id)
        .order_by(Conversation.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [
        ConversationSummary(
            id=row.id,
            title=row.title,
            created_at=row.created_at,
            updated_at=row.updated_at,
            message_count=len(row.messages),
        )
        for row in rows
    ]


@router.get(
    "/conversations/{conversation_id}",
    response_model=ConversationDetail,
)
def get_conversation(
    conversation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ConversationDetail:
    """One conversation with its messages; owner only (else 404)."""
    try:
        conv_uuid = uuid.UUID(conversation_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found",
        ) from None
    row = (
        db.query(Conversation)
        .filter(Conversation.id == conv_uuid)
        .first()
    )
    if row is None or row.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found",
        )
    messages = (
        db.query(ConversationMessage)
        .filter(ConversationMessage.conversation_id == row.id)
        .order_by(ConversationMessage.created_at.asc())
        .all()
    )
    return ConversationDetail(
        id=row.id,
        title=row.title,
        created_at=row.created_at,
        updated_at=row.updated_at,
        messages=[
            ConversationMessageOut(
                id=m.id,
                role=m.role,
                content=m.content,
                citations=m.citations,
                created_at=m.created_at,
            )
            for m in messages
        ],
    )


@router.delete(
    "/conversations/{conversation_id}", status_code=204
)
def delete_conversation(
    conversation_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    """Delete a conversation; owner only (else 404)."""
    try:
        conv_uuid = uuid.UUID(conversation_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found",
        ) from None
    row = (
        db.query(Conversation)
        .filter(Conversation.id == conv_uuid)
        .first()
    )
    if row is None or row.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found",
        )
    db.delete(row)
    db.commit()
    return None
