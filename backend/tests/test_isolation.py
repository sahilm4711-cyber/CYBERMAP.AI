"""Data-isolation tests (Phase 3 — CRITICAL).

User A must not be able to read, update or delete user B's research
data. Phase 8 APIs do not exist yet, so the ownership boundary is
tested at the service layer through ``assert_owns_or_404`` /
``owned_or_404`` — the helper every later repository query must use —
plus the admin-only role guard over HTTP.
"""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import ResearchCollection, ResearchNote, Role, User
from app.services.ownership import assert_owns_or_404, owned_or_404
from tests.conftest import login_user, register_user


def _make_users(client: TestClient, db_session: Session):
    """Register A and B via the API; return (user_a, user_b) ORM rows."""
    register_user(client, "alice")
    register_user(client, "bob")
    user_a = db_session.query(User).filter(User.username == "alice").first()
    user_b = db_session.query(User).filter(User.username == "bob").first()
    assert user_a is not None and user_b is not None
    return user_a, user_b


def _make_collection_and_note(db_session: Session, user_a: User):
    collection = ResearchCollection(
        user_id=user_a.id,
        name="A's web research",
        description="Private collection",
    )
    db_session.add(collection)
    db_session.commit()
    note = ResearchNote(
        user_id=user_a.id,
        collection_id=collection.id,
        title="A's note",
        body="Private findings",
    )
    db_session.add(note)
    db_session.commit()
    return collection, note


def test_owner_can_access_own_collection_and_note(
    client: TestClient, db_session: Session
):
    user_a, _ = _make_users(client, db_session)
    collection, note = _make_collection_and_note(db_session, user_a)
    assert owned_or_404(collection, user_a.id) is collection
    assert owned_or_404(note, user_a.id) is note


def test_other_user_cannot_read_owners_collection(
    client: TestClient, db_session: Session
):
    user_a, user_b = _make_users(client, db_session)
    collection, _ = _make_collection_and_note(db_session, user_a)
    with pytest.raises(HTTPException) as exc:
        owned_or_404(collection, user_b.id)
    assert exc.value.status_code == 404


def test_other_user_cannot_read_update_or_delete_owners_note(
    client: TestClient, db_session: Session
):
    user_a, user_b = _make_users(client, db_session)
    _, note = _make_collection_and_note(db_session, user_a)
    # Read.
    with pytest.raises(HTTPException) as exc:
        owned_or_404(note, user_b.id)
    assert exc.value.status_code == 404
    # Update / delete go through the same helper, so the same 404
    # applies — the object is never handed to the caller.
    with pytest.raises(HTTPException):
        assert_owns_or_404(note, note.user_id, user_b.id)
    # And B's attempt must not have changed or removed A's note.
    still_there = (
        db_session.query(ResearchNote).filter(ResearchNote.id == note.id).first()
    )
    assert still_there is not None
    assert still_there.body == "Private findings"


def test_missing_object_is_404_not_500(
    client: TestClient, db_session: Session
):
    user_a, _ = _make_users(client, db_session)
    with pytest.raises(HTTPException) as exc:
        owned_or_404(None, user_a.id)
    assert exc.value.status_code == 404


def test_admin_only_endpoint_forbidden_for_normal_user(client: TestClient):
    register_user(client, "alice")
    login_user(client, "alice")
    resp = client.get("/api/v1/auth/admin/ping")
    assert resp.status_code == 403


def test_admin_only_endpoint_allowed_for_admin(
    client: TestClient, db_session: Session
):
    register_user(client, "alice")
    # Promote alice to admin directly (no API allows self-promotion).
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    user = db_session.query(User).filter(User.username == "alice").first()
    assert admin_role is not None and user is not None
    user.role_id = admin_role.id
    db_session.commit()
    login_user(client, "alice")
    resp = client.get("/api/v1/auth/admin/ping")
    assert resp.status_code == 200
    assert "admin ok" in resp.json()["detail"]


def test_admin_cannot_read_other_users_private_note_via_helper(
    client: TestClient, db_session: Session
):
    """Admin powers cover ingestion/users — not other users' research."""
    user_a, user_b = _make_users(client, db_session)
    _, note = _make_collection_and_note(db_session, user_a)
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    user_b.role_id = admin_role.id
    db_session.commit()
    with pytest.raises(HTTPException) as exc:
        owned_or_404(note, user_b.id)
    assert exc.value.status_code == 404
