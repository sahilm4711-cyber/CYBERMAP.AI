"""Research workspace service — Phase 8 (DATABASE.md §2.14–2.17).

Isolation rule (ARCHITECTURE.md §8): every query filters by the
caller's ``user_id``; single-object access goes through
``owned_or_404`` so another user's object returns 404 (not 403).

Bookmarks design decision: bookmarks are NOT a separate table.
They are a per-user collection named ``"Bookmarks"`` (``is_public``
false), auto-created on first bookmark use, and its items are plain
``collection_items`` rows. This keeps one code path for items,
dedupe (unique constraint) and deletion, and the "Bookmarks"
collection itself is visible in the collections list so the user
can see and manage it like any other collection.
"""

import csv
import io
import uuid

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import (
    AttackTechnique,
    CollectionItem,
    CweEntry,
    EpssScore,
    KevEntry,
    ResearchCollection,
    ResearchNote,
    SavedAnalysis,
    User,
    Vulnerability,
    VulnerabilityRelationship,
)
from app.services.ownership import owned_or_404

BOOKMARKS_NAME = "Bookmarks"

# Investigation-status convention (no model change allowed in
# Phase 8): a collection's status is tracked by a note linked to
# the collection whose ``tags`` contain ``"status"`` and whose
# ``title`` holds the status value (e.g. "investigating"). The
# latest such note wins; no status note means "not_started".
STATUS_TAG = "status"
DEFAULT_STATUS = "not_started"

_ENTITY_MODELS = {
    "vulnerability": (Vulnerability, "cve_id"),
    "cwe": (CweEntry, "cwe_id"),
    "attack_technique": (AttackTechnique, "technique_id"),
}


def resolve_entity(
    db: Session, item_type: str, item_id: uuid.UUID
) -> tuple[str, str | None]:
    """Return ``(label, name)`` for a referenced entity, or 404.

    ``label`` is the natural id (CVE-… / CWE-… / T…); ``name`` is
    the human-readable name/title where the model has one.
    """
    entry = _ENTITY_MODELS.get(item_type)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown item_type: {item_type!r}",
        )
    model, label_col = entry
    row = db.query(model).filter(model.id == item_id).first()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced {item_type} not found",
        )
    label = getattr(row, label_col)
    name = getattr(row, "name", None) or getattr(row, "title", None)
    return label, name


def get_owned_collection(
    db: Session, user_id: uuid.UUID, collection_id: uuid.UUID
) -> ResearchCollection:
    """Fetch a collection the caller owns, or raise 404."""
    collection = (
        db.query(ResearchCollection)
        .filter(ResearchCollection.id == collection_id)
        .first()
    )
    return owned_or_404(collection, user_id)


def collection_item_count(db: Session, collection_id: uuid.UUID) -> int:
    return (
        db.query(CollectionItem)
        .filter(CollectionItem.collection_id == collection_id)
        .count()
    )


def create_collection(
    db: Session, user: User, name: str, description: str | None,
    is_public: bool,
) -> ResearchCollection:
    collection = ResearchCollection(
        user_id=user.id,
        name=name,
        description=description,
        is_public=is_public,
    )
    db.add(collection)
    db.commit()
    db.refresh(collection)
    return collection


def get_or_create_bookmarks_collection(
    db: Session, user: User
) -> ResearchCollection:
    """The user's "Bookmarks" collection; created on first use."""
    collection = (
        db.query(ResearchCollection)
        .filter(
            ResearchCollection.user_id == user.id,
            ResearchCollection.name == BOOKMARKS_NAME,
        )
        .first()
    )
    if collection is None:
        collection = ResearchCollection(
            user_id=user.id,
            name=BOOKMARKS_NAME,
            description=(
                "Items bookmarked from the research workspace. "
                "Managed automatically; delete items here to remove "
                "a bookmark."
            ),
            is_public=False,
        )
        db.add(collection)
        db.commit()
        db.refresh(collection)
    return collection


def add_item_to_collection(
    db: Session,
    collection: ResearchCollection,
    item_type: str,
    item_id: uuid.UUID,
) -> tuple[CollectionItem, bool]:
    """Add an item; returns ``(item, created)``.

    Adding the same item twice is idempotent: the unique
    constraint (collection_id, item_type, item_id) means the
    existing row is returned with ``created=False``.
    """
    resolve_entity(db, item_type, item_id)
    existing = (
        db.query(CollectionItem)
        .filter(
            CollectionItem.collection_id == collection.id,
            CollectionItem.item_type == item_type,
            CollectionItem.item_id == item_id,
        )
        .first()
    )
    if existing is not None:
        return existing, False
    item = CollectionItem(
        collection_id=collection.id,
        item_type=item_type,
        item_id=item_id,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item, True


def remove_item_from_collection(
    db: Session,
    collection: ResearchCollection,
    item_type: str,
    item_id: uuid.UUID,
) -> None:
    item = (
        db.query(CollectionItem)
        .filter(
            CollectionItem.collection_id == collection.id,
            CollectionItem.item_type == item_type,
            CollectionItem.item_id == item_id,
        )
        .first()
    )
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found in collection",
        )
    db.delete(item)
    db.commit()


def list_collection_items(
    db: Session, collection: ResearchCollection, skip: int, limit: int
) -> tuple[list[CollectionItem], int]:
    query = (
        db.query(CollectionItem)
        .filter(CollectionItem.collection_id == collection.id)
        .order_by(CollectionItem.added_at)
    )
    total = query.count()
    return query.offset(skip).limit(limit).all(), total


def item_out(db: Session, item: CollectionItem) -> dict:
    label, name = resolve_entity(db, item.item_type, item.item_id)
    return {
        "id": item.id,
        "collection_id": item.collection_id,
        "item_type": item.item_type,
        "item_id": item.item_id,
        "label": label,
        "name": name,
        "added_at": item.added_at,
    }


def get_owned_note(
    db: Session, user_id: uuid.UUID, note_id: uuid.UUID
) -> ResearchNote:
    note = (
        db.query(ResearchNote)
        .filter(ResearchNote.id == note_id)
        .first()
    )
    return owned_or_404(note, user_id)


def get_owned_analysis(
    db: Session, user_id: uuid.UUID, analysis_id: uuid.UUID
) -> SavedAnalysis:
    analysis = (
        db.query(SavedAnalysis)
        .filter(SavedAnalysis.id == analysis_id)
        .first()
    )
    return owned_or_404(analysis, user_id)


def validate_note_links(
    db: Session,
    user_id: uuid.UUID,
    collection_id: uuid.UUID | None,
    vulnerability_id: uuid.UUID | None,
) -> None:
    """A note may only link to the caller's own collection and to
    a vulnerability that exists. 404 either way (no leakage)."""
    if collection_id is not None:
        get_owned_collection(db, user_id, collection_id)
    if vulnerability_id is not None:
        vuln = (
            db.query(Vulnerability)
            .filter(Vulnerability.id == vulnerability_id)
            .first()
        )
        if vuln is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Referenced vulnerability not found",
            )


def collection_status(
    db: Session, collection: ResearchCollection
) -> dict:
    """Latest status-tagged note wins; none means "not_started"."""
    notes = (
        db.query(ResearchNote)
        .filter(ResearchNote.collection_id == collection.id)
        .order_by(ResearchNote.created_at.desc())
        .all()
    )
    for note in notes:
        tags = note.tags or []
        if STATUS_TAG in tags or any(
            isinstance(t, str) and t.startswith("status:")
            for t in tags
        ):
            value = note.title or DEFAULT_STATUS
            if value.startswith("status:"):
                value = value[len("status:"):]
            return {
                "collection_id": collection.id,
                "status": value,
                "note_id": note.id,
                "note_title": note.title,
            }
    return {
        "collection_id": collection.id,
        "status": DEFAULT_STATUS,
        "note_id": None,
        "note_title": None,
    }


def compare_cves(db: Session, cve_ids: list[str]) -> list[dict]:
    """Side-by-side comparison rows, built from the DB.

    Unknown CVE ID -> 404. Missing fields are reported as the
    string ``"unavailable"`` rather than invented.
    """
    rows: list[dict] = []
    for cve_id in cve_ids:
        vuln = (
            db.query(Vulnerability)
            .filter(Vulnerability.cve_id == cve_id)
            .first()
        )
        if vuln is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown CVE: {cve_id}",
            )
        cwe_ids: list[str] = []
        rels = (
            db.query(VulnerabilityRelationship)
            .filter(
                VulnerabilityRelationship.from_type == "vulnerability",
                VulnerabilityRelationship.from_id == vuln.id,
                VulnerabilityRelationship.to_type == "cwe",
                VulnerabilityRelationship.relationship == "HAS_WEAKNESS",
            )
            .all()
        )
        if rels:
            cwe_rows = (
                db.query(CweEntry)
                .filter(
                    CweEntry.id.in_([r.to_id for r in rels])
                )
                .all()
            )
            cwe_ids = [c.cwe_id for c in cwe_rows]
        epss = (
            db.query(EpssScore)
            .filter(EpssScore.cve_id == cve_id)
            .order_by(EpssScore.model_date.desc())
            .first()
        )
        kev = (
            db.query(KevEntry)
            .filter(KevEntry.cve_id == cve_id)
            .first()
        )
        rows.append(
            {
                "cve_id": vuln.cve_id,
                "cvss_score": (
                    float(vuln.cvss_score)
                    if vuln.cvss_score is not None
                    else "unavailable"
                ),
                "severity": vuln.severity or "unavailable",
                "cwe_ids": cwe_ids,
                "epss_score": (
                    float(epss.epss_score)
                    if epss is not None
                    else "unavailable"
                ),
                "epss_percentile": (
                    float(epss.percentile)
                    if epss is not None
                    else "unavailable"
                ),
                "kev_listed": kev is not None,
                "published_at": (
                    vuln.published_at.isoformat()
                    if vuln.published_at is not None
                    else "unavailable"
                ),
            }
        )
    return rows


def export_collection_json(
    db: Session, collection: ResearchCollection
) -> dict:
    """Full collection: resolved items + the owner's linked notes."""
    items, _ = list_collection_items(db, collection, 0, 10000)
    notes = (
        db.query(ResearchNote)
        .filter(ResearchNote.collection_id == collection.id)
        .order_by(ResearchNote.created_at)
        .all()
    )
    return {
        "collection": {
            "id": str(collection.id),
            "name": collection.name,
            "description": collection.description,
            "is_public": collection.is_public,
            "created_at": (
                collection.created_at.isoformat()
                if collection.created_at
                else None
            ),
        },
        "items": [item_out(db, item) for item in items],
        "notes": [
            {
                "id": str(n.id),
                "title": n.title,
                "body": n.body,
                "tags": n.tags,
                "created_at": (
                    n.created_at.isoformat() if n.created_at else None
                ),
            }
            for n in notes
        ],
    }


def export_collection_csv(
    db: Session, collection: ResearchCollection
) -> str:
    """One row per item: collection, item_type, item_id, label,
    added_at."""
    items, _ = list_collection_items(db, collection, 0, 10000)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["collection", "item_type", "item_id", "label", "added_at"]
    )
    for item in items:
        label, _ = resolve_entity(db, item.item_type, item.item_id)
        writer.writerow(
            [
                collection.name,
                item.item_type,
                str(item.item_id),
                label,
                item.added_at.isoformat() if item.added_at else "",
            ]
        )
    return buf.getvalue()


def analysis_out(db: Session, analysis: SavedAnalysis) -> dict:
    vuln = (
        db.query(Vulnerability)
        .filter(Vulnerability.id == analysis.vulnerability_id)
        .first()
    )
    return {
        "id": analysis.id,
        "vulnerability_id": analysis.vulnerability_id,
        "cve_id": vuln.cve_id if vuln else None,
        "analysis_type": analysis.analysis_type,
        "content": analysis.content,
        "ai_mode": analysis.ai_mode,
        "model": analysis.model,
        "created_at": analysis.created_at,
    }


def collection_out(
    db: Session, collection: ResearchCollection
) -> dict:
    return {
        "id": collection.id,
        "name": collection.name,
        "description": collection.description,
        "is_public": collection.is_public,
        "item_count": collection_item_count(db, collection.id),
        "created_at": collection.created_at,
        "updated_at": collection.updated_at,
    }
