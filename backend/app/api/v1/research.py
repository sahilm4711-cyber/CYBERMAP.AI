"""Research workspace API — ``/api/v1/research`` (Phase 8).

NOTE: this router is intentionally NOT registered in
``app/main.py`` — the coordinator registers routers (same pattern
as the Phase 6 AI router).

Isolation: every query filters by the caller's ``user_id`` and
every single-object access returns 404 (not 403) for another
user's data, so ownership cannot be probed.

Bookmarks are a per-user collection named ``"Bookmarks"``,
auto-created on first use (see ``app.services.research_service``).

Investigation status: there is no status column on collections
(Phase 8 may not modify models). Status is tracked via a note
linked to the collection whose tags contain ``"status"`` and whose
title holds the status value (e.g. ``"investigating"``);
``GET /collections/{id}/status`` reads the latest such note and
returns ``"not_started"`` when none exists.
"""

import json
import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import (
    ResearchCollection,
    ResearchNote,
    SavedAnalysis,
    User,
)
from app.schemas.research import (
    BookmarkCreate,
    CollectionCreate,
    CollectionItemCreate,
    CollectionItemOut,
    CollectionOut,
    CollectionStatusOut,
    CompareRequest,
    CompareResponse,
    CompareRow,
    NoteCreate,
    NoteOut,
    NoteUpdate,
    PaginatedAnalyses,
    PaginatedCollections,
    PaginatedItems,
    PaginatedNotes,
    SavedAnalysisOut,
    CollectionUpdate,
)
from app.security.csrf import verify_origin
from app.security.dependencies import get_current_user
from app.services import research_service as svc

router = APIRouter(
    prefix="/api/v1/research",
    tags=["research"],
    dependencies=[Depends(verify_origin)],
)


# ------------------------------------------------------------------
# Collections
# ------------------------------------------------------------------


@router.post(
    "/collections",
    response_model=CollectionOut,
    status_code=status.HTTP_201_CREATED,
)
def create_collection(
    payload: CollectionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CollectionOut:
    collection = svc.create_collection(
        db, user, payload.name, payload.description, payload.is_public
    )
    return CollectionOut(**svc.collection_out(db, collection))


@router.get("/collections", response_model=PaginatedCollections)
def list_collections(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PaginatedCollections:
    query = (
        db.query(ResearchCollection)
        .filter(ResearchCollection.user_id == user.id)
        .order_by(ResearchCollection.created_at.desc())
    )
    total = query.count()
    rows = query.offset(skip).limit(limit).all()
    return PaginatedCollections(
        items=[CollectionOut(**svc.collection_out(db, c)) for c in rows],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/collections/{collection_id}", response_model=CollectionOut)
def get_collection(
    collection_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CollectionOut:
    collection = svc.get_owned_collection(db, user.id, collection_id)
    return CollectionOut(**svc.collection_out(db, collection))


@router.patch("/collections/{collection_id}", response_model=CollectionOut)
def update_collection(
    collection_id: uuid.UUID,
    payload: CollectionUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CollectionOut:
    collection = svc.get_owned_collection(db, user.id, collection_id)
    if payload.name is not None:
        collection.name = payload.name
    if payload.description is not None:
        collection.description = payload.description
    if payload.is_public is not None:
        collection.is_public = payload.is_public
    db.commit()
    db.refresh(collection)
    return CollectionOut(**svc.collection_out(db, collection))


@router.delete("/collections/{collection_id}", status_code=204)
def delete_collection(
    collection_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    collection = svc.get_owned_collection(db, user.id, collection_id)
    db.delete(collection)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/collections/{collection_id}/status",
    response_model=CollectionStatusOut,
)
def get_collection_status(
    collection_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CollectionStatusOut:
    collection = svc.get_owned_collection(db, user.id, collection_id)
    return CollectionStatusOut(**svc.collection_status(db, collection))


# ------------------------------------------------------------------
# Collection items
# ------------------------------------------------------------------


@router.post(
    "/collections/{collection_id}/items",
    response_model=CollectionItemOut,
)
def add_collection_item(
    collection_id: uuid.UUID,
    payload: CollectionItemCreate,
    response: Response,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CollectionItemOut:
    collection = svc.get_owned_collection(db, user.id, collection_id)
    item, created = svc.add_item_to_collection(
        db, collection, payload.item_type, payload.item_id
    )
    # Idempotent duplicate: 200 with the existing item; new item: 201.
    response.status_code = (
        status.HTTP_201_CREATED if created else status.HTTP_200_OK
    )
    return CollectionItemOut(**svc.item_out(db, item))


@router.get(
    "/collections/{collection_id}/items",
    response_model=PaginatedItems,
)
def list_collection_items(
    collection_id: uuid.UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PaginatedItems:
    collection = svc.get_owned_collection(db, user.id, collection_id)
    items, total = svc.list_collection_items(db, collection, skip, limit)
    return PaginatedItems(
        items=[CollectionItemOut(**svc.item_out(db, i)) for i in items],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.delete(
    "/collections/{collection_id}/items/{item_id}",
    status_code=204,
)
def remove_collection_item(
    collection_id: uuid.UUID,
    item_id: uuid.UUID,
    item_type: str = Query(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    collection = svc.get_owned_collection(db, user.id, collection_id)
    svc.remove_item_from_collection(db, collection, item_type, item_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------
# Export
# ------------------------------------------------------------------


@router.get("/collections/{collection_id}/export")
def export_collection(
    collection_id: uuid.UUID,
    format: str = Query("json", pattern="^(json|csv)$"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    collection = svc.get_owned_collection(db, user.id, collection_id)
    filename = f"collection-{collection.id}"
    if format == "csv":
        body = svc.export_collection_csv(db, collection)
        return Response(
            content=body,
            media_type="text/csv",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{filename}.csv"'
                )
            },
        )
    body = json.dumps(
        svc.export_collection_json(db, collection), default=str
    )
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}.json"'
            )
        },
    )


# ------------------------------------------------------------------
# Bookmarks (a "Bookmarks" collection, auto-created per user)
# ------------------------------------------------------------------


@router.post("/bookmarks", response_model=CollectionItemOut)
def add_bookmark(
    payload: BookmarkCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CollectionItemOut:
    collection = svc.get_or_create_bookmarks_collection(db, user)
    item, _created = svc.add_item_to_collection(
        db, collection, payload.item_type, payload.item_id
    )
    return CollectionItemOut(**svc.item_out(db, item))


@router.get("/bookmarks", response_model=PaginatedItems)
def list_bookmarks(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PaginatedItems:
    collection = (
        db.query(ResearchCollection)
        .filter(
            ResearchCollection.user_id == user.id,
            ResearchCollection.name == svc.BOOKMARKS_NAME,
        )
        .first()
    )
    if collection is None:
        return PaginatedItems(items=[], total=0, skip=skip, limit=limit)
    items, total = svc.list_collection_items(db, collection, skip, limit)
    return PaginatedItems(
        items=[CollectionItemOut(**svc.item_out(db, i)) for i in items],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.delete("/bookmarks/{item_type}/{item_id}", status_code=204)
def remove_bookmark(
    item_type: str,
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    collection = svc.get_or_create_bookmarks_collection(db, user)
    svc.remove_item_from_collection(db, collection, item_type, item_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------
# Notes
# ------------------------------------------------------------------


@router.post(
    "/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED
)
def create_note(
    payload: NoteCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> NoteOut:
    svc.validate_note_links(
        db, user.id, payload.collection_id, payload.vulnerability_id
    )
    note = ResearchNote(
        user_id=user.id,
        title=payload.title,
        body=payload.body,
        tags=payload.tags,
        collection_id=payload.collection_id,
        vulnerability_id=payload.vulnerability_id,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return NoteOut(**_note_dict(note))


def _note_dict(note: ResearchNote) -> dict:
    return {
        "id": note.id,
        "collection_id": note.collection_id,
        "vulnerability_id": note.vulnerability_id,
        "title": note.title,
        "body": note.body,
        "tags": note.tags,
        "created_at": note.created_at,
        "updated_at": note.updated_at,
    }


@router.get("/notes", response_model=PaginatedNotes)
def list_notes(
    collection_id: uuid.UUID | None = None,
    vulnerability_id: uuid.UUID | None = None,
    tag: str | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PaginatedNotes:
    query = (
        db.query(ResearchNote)
        .filter(ResearchNote.user_id == user.id)
        .order_by(ResearchNote.created_at.desc())
    )
    if collection_id is not None:
        query = query.filter(
            ResearchNote.collection_id == collection_id
        )
    if vulnerability_id is not None:
        query = query.filter(
            ResearchNote.vulnerability_id == vulnerability_id
        )
    rows = query.all()
    if tag is not None:
        rows = [n for n in rows if n.tags and tag in n.tags]
    total = len(rows)
    page = rows[skip : skip + limit]
    return PaginatedNotes(
        items=[NoteOut(**_note_dict(n)) for n in page],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/notes/{note_id}", response_model=NoteOut)
def get_note(
    note_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> NoteOut:
    note = svc.get_owned_note(db, user.id, note_id)
    return NoteOut(**_note_dict(note))


@router.patch("/notes/{note_id}", response_model=NoteOut)
def update_note(
    note_id: uuid.UUID,
    payload: NoteUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> NoteOut:
    note = svc.get_owned_note(db, user.id, note_id)
    new_collection = (
        payload.collection_id
        if payload.collection_id is not None
        else note.collection_id
    )
    new_vuln = (
        payload.vulnerability_id
        if payload.vulnerability_id is not None
        else note.vulnerability_id
    )
    svc.validate_note_links(db, user.id, new_collection, new_vuln)
    if payload.title is not None:
        note.title = payload.title
    if payload.body is not None:
        note.body = payload.body
    if payload.tags is not None:
        note.tags = payload.tags
    note.collection_id = new_collection
    note.vulnerability_id = new_vuln
    db.commit()
    db.refresh(note)
    return NoteOut(**_note_dict(note))


@router.delete("/notes/{note_id}", status_code=204)
def delete_note(
    note_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    note = svc.get_owned_note(db, user.id, note_id)
    db.delete(note)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------
# Saved analyses (written by Phase 6)
# ------------------------------------------------------------------


@router.get("/analyses", response_model=PaginatedAnalyses)
def list_analyses(
    vulnerability_id: uuid.UUID | None = None,
    analysis_type: str | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PaginatedAnalyses:
    query = (
        db.query(SavedAnalysis)
        .filter(SavedAnalysis.user_id == user.id)
        .order_by(SavedAnalysis.created_at.desc())
    )
    if vulnerability_id is not None:
        query = query.filter(
            SavedAnalysis.vulnerability_id == vulnerability_id
        )
    if analysis_type is not None:
        query = query.filter(
            SavedAnalysis.analysis_type == analysis_type
        )
    total = query.count()
    rows = query.offset(skip).limit(limit).all()
    return PaginatedAnalyses(
        items=[SavedAnalysisOut(**svc.analysis_out(db, a)) for a in rows],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/analyses/{analysis_id}", response_model=SavedAnalysisOut)
def get_analysis(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> SavedAnalysisOut:
    analysis = svc.get_owned_analysis(db, user.id, analysis_id)
    return SavedAnalysisOut(**svc.analysis_out(db, analysis))


@router.delete("/analyses/{analysis_id}", status_code=204)
def delete_analysis(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    analysis = svc.get_owned_analysis(db, user.id, analysis_id)
    db.delete(analysis)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------
# Comparison (no persistence)
# ------------------------------------------------------------------


@router.post("/compare", response_model=CompareResponse)
def compare(
    payload: CompareRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CompareResponse:
    rows = svc.compare_cves(db, payload.cve_ids)
    return CompareResponse(comparisons=[CompareRow(**r) for r in rows])
