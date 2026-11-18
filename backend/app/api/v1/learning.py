"""Learning center API — ``/api/v1/learning`` (Phase 8).

NOTE: this router is intentionally NOT registered in
``app/main.py`` — the coordinator registers routers (same pattern
as the Phase 6 AI router).

All endpoints require a logged-in user. Content is educational
text written for this project; the ``related_real_records`` in a
topic detail are real vulnerability rows from the database,
clearly labelled as such and separate from the educational text.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import User
from app.security.dependencies import get_current_user
from app.services import learning_service as svc

router = APIRouter(prefix="/api/v1/learning", tags=["learning"])


@router.get("/topics")
def list_topics(
    user: User = Depends(get_current_user),
) -> dict:
    return {"topics": svc.list_topics()}


@router.get("/topics/{slug}")
def get_topic(
    slug: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    topic = svc.get_topic(slug)
    if topic is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown learning topic: {slug}",
        )
    related = svc.related_real_records(
        db, topic.get("related_cwe_ids", [])
    )
    return {**topic, "related_real_records": related}
