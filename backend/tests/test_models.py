"""Model tests (Phase 3).

Creates every model, verifies unique constraints, foreign-key
integrity, timestamps, and the SQLite JSON fallback for the
embeddings vector column. Runs on the fresh temp DB per test.
"""

from datetime import date

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    AffectedProduct,
    AttackTechnique,
    AuditLog,
    CollectionItem,
    Conversation,
    ConversationMessage,
    CweEntry,
    DataSource,
    Embedding,
    EpssScore,
    IngestionJob,
    KevEntry,
    ResearchCollection,
    ResearchNote,
    Role,
    SavedAnalysis,
    User,
    UserSession,
    Vulnerability,
    VulnerabilityReference,
    VulnerabilityRelationship,
)
from app.services import auth_service
from app.services.seed import get_role


@pytest.fixture()
def user(db_session: Session) -> User:
    role = get_role(db_session, "user")
    user = User(
        username="model-user",
        email="model@example.com",
        password_hash="hashed",
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture()
def vulnerability(db_session: Session) -> Vulnerability:
    vuln = Vulnerability(
        cve_id="CVE-2024-12345",
        description="A test vulnerability.",
        source="nvd",
    )
    db_session.add(vuln)
    db_session.commit()
    return vuln


def test_roles_and_sources_seeded(db_session: Session):
    assert sorted(r.name for r in db_session.query(Role).all()) == [
        "admin",
        "researcher",
        "user",
    ]
    assert sorted(s.name for s in db_session.query(DataSource).all()) == [
        "cisa-kev",
        "epss",
        "mitre-attack",
        "mitre-cwe",
        "nvd",
    ]


def test_all_21_tables_exist(db_session: Session):
    from app.core.database import Base

    assert len(Base.metadata.tables) == 21


def test_user_timestamps_set(user: User):
    assert user.created_at is not None
    assert user.updated_at is not None


def test_duplicate_username_rejected(db_session: Session, user: User):
    role = get_role(db_session, "user")
    db_session.add(
        User(
            username="model-user",
            email="other@example.com",
            password_hash="x",
            role_id=role.id,
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_duplicate_email_rejected(db_session: Session, user: User):
    role = get_role(db_session, "user")
    db_session.add(
        User(
            username="other-user",
            email="model@example.com",
            password_hash="x",
            role_id=role.id,
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_user_session_stores_hash_only(
    db_session: Session, user: User
):
    _, raw_token = auth_service.create_session(db_session, user)
    row = db_session.query(UserSession).filter(
        UserSession.user_id == user.id
    ).first()
    assert row is not None
    assert row.session_token_hash != raw_token
    assert len(row.session_token_hash) == 64  # SHA-256 hex
    assert row.expires_at is not None


def test_duplicate_cve_id_rejected(
    db_session: Session, vulnerability: Vulnerability
):
    db_session.add(
        Vulnerability(
            cve_id="CVE-2024-12345",
            description="Duplicate.",
            source="nvd",
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_vulnerability_reference_unique_pair(
    db_session: Session, vulnerability: Vulnerability
):
    ref = VulnerabilityReference(
        vulnerability_id=vulnerability.id,
        url="https://example.com/advisory",
    )
    db_session.add(ref)
    db_session.commit()
    db_session.add(
        VulnerabilityReference(
            vulnerability_id=vulnerability.id,
            url="https://example.com/advisory",
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_affected_product_and_cascade_delete(
    db_session: Session, vulnerability: Vulnerability
):
    db_session.add(
        AffectedProduct(
            vulnerability_id=vulnerability.id,
            vendor="acme",
            product="widget",
        )
    )
    db_session.add(
        VulnerabilityReference(
            vulnerability_id=vulnerability.id,
            url="https://example.com/x",
        )
    )
    db_session.commit()
    db_session.delete(vulnerability)
    db_session.commit()
    assert db_session.query(AffectedProduct).count() == 0
    assert db_session.query(VulnerabilityReference).count() == 0


def test_cwe_and_technique_natural_keys(
    db_session: Session,
):
    db_session.add(CweEntry(cwe_id="CWE-79", name="XSS", source="mitre-cwe"))
    db_session.add(
        AttackTechnique(
            technique_id="T1059.001",
            name="PowerShell",
            source="mitre-attack",
        )
    )
    db_session.commit()
    db_session.add(CweEntry(cwe_id="CWE-79", name="dup", source="mitre-cwe"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
    db_session.add(
        AttackTechnique(
            technique_id="T1059.001", name="dup", source="mitre-attack"
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_relationship_unique_edge(
    db_session: Session, vulnerability: Vulnerability
):
    cwe = CweEntry(cwe_id="CWE-79", name="XSS", source="mitre-cwe")
    db_session.add(cwe)
    db_session.commit()
    edge = VulnerabilityRelationship(
        from_type="vulnerability",
        from_id=vulnerability.id,
        to_type="cwe",
        to_id=cwe.id,
        relationship="HAS_WEAKNESS",
        source="nvd",
    )
    db_session.add(edge)
    db_session.commit()
    db_session.add(
        VulnerabilityRelationship(
            from_type="vulnerability",
            from_id=vulnerability.id,
            to_type="cwe",
            to_id=cwe.id,
            relationship="HAS_WEAKNESS",
            source="nvd",
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_kev_and_epss(
    db_session: Session, vulnerability: Vulnerability
):
    db_session.add(
        KevEntry(
            cve_id="CVE-2024-12345",
            vulnerability_id=vulnerability.id,
            source="cisa-kev",
        )
    )
    db_session.add(
        EpssScore(
            cve_id="CVE-2024-12345",
            vulnerability_id=vulnerability.id,
            epss_score="0.12345",
            percentile="0.98765",
            model_date=date(2026, 11, 17),
        )
    )
    db_session.commit()
    # One EPSS row per CVE per model date.
    db_session.add(
        EpssScore(
            cve_id="CVE-2024-12345",
            epss_score="0.5",
            percentile="0.5",
            model_date=date(2026, 11, 17),
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_ingestion_job_links_to_source(db_session: Session):
    source = db_session.query(DataSource).filter(
        DataSource.name == "nvd"
    ).first()
    job = IngestionJob(source_id=source.id, status="success")
    db_session.add(job)
    db_session.commit()
    assert job.source.name == "nvd"
    assert job.records_fetched == 0


def test_collection_item_unique_triplet(
    db_session: Session, user: User, vulnerability: Vulnerability
):
    collection = ResearchCollection(user_id=user.id, name="c1")
    db_session.add(collection)
    db_session.commit()
    db_session.add(
        CollectionItem(
            collection_id=collection.id,
            item_type="vulnerability",
            item_id=vulnerability.id,
        )
    )
    db_session.commit()
    db_session.add(
        CollectionItem(
            collection_id=collection.id,
            item_type="vulnerability",
            item_id=vulnerability.id,
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_research_note_fk_integrity(db_session: Session):
    # A note pointing at a non-existent user must fail (FK enforced).
    import uuid

    db_session.add(
        ResearchNote(user_id=uuid.uuid4(), body="orphan note")
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_saved_analysis_and_conversation(
    db_session: Session, user: User, vulnerability: Vulnerability
):
    db_session.add(
        SavedAnalysis(
            user_id=user.id,
            vulnerability_id=vulnerability.id,
            analysis_type="simple",
            content={"summary": "test"},
            ai_mode="fallback",
        )
    )
    convo = Conversation(user_id=user.id, title="chat")
    db_session.add(convo)
    db_session.commit()
    db_session.add(
        ConversationMessage(
            conversation_id=convo.id,
            role="user",
            content="What is CVE-2024-12345?",
        )
    )
    db_session.commit()
    assert db_session.query(SavedAnalysis).count() == 1
    assert db_session.query(ConversationMessage).count() == 1


def test_embedding_json_fallback_on_sqlite(
    db_session: Session, vulnerability: Vulnerability
):
    # SQLite stores the vector as JSON (DATABASE.md §3 fallback).
    db_session.add(
        Embedding(
            entity_type="vulnerability",
            entity_id=vulnerability.id,
            chunk_text="test chunk",
            embedding=[0.1, 0.2, 0.3],
            model="test-model",
        )
    )
    db_session.commit()
    row = db_session.query(Embedding).first()
    assert row.embedding == [0.1, 0.2, 0.3]
    # Unique per (entity_type, entity_id, model).
    db_session.add(
        Embedding(
            entity_type="vulnerability",
            entity_id=vulnerability.id,
            chunk_text="dup",
            embedding=[0.0],
            model="test-model",
        )
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_audit_log_append_only_fields(
    db_session: Session, user: User
):
    db_session.add(
        AuditLog(
            user_id=user.id,
            action="auth.login",
            details={"username": user.username},
        )
    )
    db_session.commit()
    row = db_session.query(AuditLog).first()
    assert row.action == "auth.login"
    assert row.created_at is not None
    assert row.user_id == user.id


def test_deleting_user_cascades_owned_data(
    db_session: Session, user: User
):
    collection = ResearchCollection(user_id=user.id, name="c1")
    db_session.add(collection)
    db_session.commit()
    db_session.add(
        ResearchNote(user_id=user.id, body="note", collection_id=collection.id)
    )
    db_session.commit()
    db_session.delete(user)
    db_session.commit()
    assert db_session.query(ResearchCollection).count() == 0
    assert db_session.query(ResearchNote).count() == 0
