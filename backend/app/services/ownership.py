"""Ownership checks — the data-isolation rule (ARCHITECTURE.md §8).

Users can only access their own research data. Every repository /
service query for user-owned objects goes through this helper, which
returns 404 (not 403) for another user's object so ownership cannot
be probed by distinguishing "exists but not yours" from "missing".
Admins are NOT exempt here: admin powers cover ingestion and user
management, not reading other researchers' private notes.
"""

import uuid

from fastapi import HTTPException, status


def assert_owns_or_404(obj, owner_id: uuid.UUID, user_id: uuid.UUID):
    """Return ``obj`` when it belongs to ``user_id``.

    Raises 404 when ``obj`` is None or owned by someone else.
    ``obj`` must expose ``user_id`` (collections, notes, analyses,
    conversations) or the caller passes the owner id explicitly.
    """
    if obj is None or owner_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
        )
    return obj


def owned_or_404(obj, user_id: uuid.UUID):
    """Shorthand for objects that carry their own ``user_id`` column."""
    owner_id = getattr(obj, "user_id", None) if obj is not None else None
    return assert_owns_or_404(obj, owner_id, user_id)
