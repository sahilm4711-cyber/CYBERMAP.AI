"""Pydantic schemas for the research workspace API — Phase 8.

Collections, collection items, bookmarks, notes, saved analyses,
comparison and export (DATABASE.md §2.14–2.17). All list endpoints
are paginated (``skip``/``limit``) and return ``{"items", "total",
"skip", "limit"}``.
"""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

ItemType = Literal["vulnerability", "cwe", "attack_technique"]

ITEM_TYPES = ("vulnerability", "cwe", "attack_technique")


class CollectionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    is_public: bool = False


class CollectionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    is_public: bool | None = None


class CollectionOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None = None
    is_public: bool
    item_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None


class CollectionItemCreate(BaseModel):
    item_type: ItemType
    item_id: uuid.UUID


class CollectionItemOut(BaseModel):
    id: uuid.UUID
    collection_id: uuid.UUID
    item_type: str
    item_id: uuid.UUID
    label: str | None = None
    name: str | None = None
    added_at: datetime | None = None


class BookmarkCreate(BaseModel):
    item_type: ItemType
    item_id: uuid.UUID


class NoteCreate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    body: str = Field(min_length=1)
    tags: list[str] | None = None
    collection_id: uuid.UUID | None = None
    vulnerability_id: uuid.UUID | None = None


class NoteUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    body: str | None = Field(default=None, min_length=1)
    tags: list[str] | None = None
    collection_id: uuid.UUID | None = None
    vulnerability_id: uuid.UUID | None = None


class NoteOut(BaseModel):
    id: uuid.UUID
    collection_id: uuid.UUID | None = None
    vulnerability_id: uuid.UUID | None = None
    title: str | None = None
    body: str
    tags: list[str] | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class SavedAnalysisOut(BaseModel):
    id: uuid.UUID
    vulnerability_id: uuid.UUID
    cve_id: str | None = None
    analysis_type: str
    content: dict[str, Any]
    ai_mode: str
    model: str | None = None
    created_at: datetime | None = None


class CompareRequest(BaseModel):
    cve_ids: list[str] = Field(min_length=2, max_length=5)


class CompareRow(BaseModel):
    cve_id: str
    cvss_score: float | str = "unavailable"
    severity: str = "unavailable"
    cwe_ids: list[str] = Field(default_factory=list)
    epss_score: float | str = "unavailable"
    epss_percentile: float | str = "unavailable"
    kev_listed: bool = False
    published_at: str = "unavailable"


class CompareResponse(BaseModel):
    comparisons: list[CompareRow]


class CollectionStatusOut(BaseModel):
    collection_id: uuid.UUID
    status: str
    note_id: uuid.UUID | None = None
    note_title: str | None = None


class PaginatedCollections(BaseModel):
    items: list[CollectionOut]
    total: int
    skip: int
    limit: int


class PaginatedItems(BaseModel):
    items: list[CollectionItemOut]
    total: int
    skip: int
    limit: int


class PaginatedNotes(BaseModel):
    items: list[NoteOut]
    total: int
    skip: int
    limit: int


class PaginatedAnalyses(BaseModel):
    items: list[SavedAnalysisOut]
    total: int
    skip: int
    limit: int
