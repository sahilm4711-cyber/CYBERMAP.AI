"""Embeddings + RAG storage — Phase 6 (DATABASE.md §2.20).

Two embedding sources:

1. **Provider embeddings** — when a provider with an embeddings API
   is configured (OpenAI, Gemini), ``embed_texts`` calls it and the
   provider model name is recorded on each :class:`Embedding` row.
2. **Local fallback** — when no provider (or no embeddings-capable
   provider) is configured, a deterministic hashing-based embedding
   is used instead.

.. warning::
   The local fallback is **NOT semantic**. It hashes word tokens into
   a fixed 384-dimensional vector (bag-of-words hashing, L2
   normalised), so it only measures surface word overlap — it does
   not understand meaning, synonyms or paraphrase. It exists only so
   RAG plumbing, storage and ranking work offline and in tests.
   Real semantic search needs a configured provider or
   sentence-transformers on Postgres (see ``docs/AI_PIPELINE.md``).

Chunks are built per entity type (see :func:`build_chunk_text`) and
truncated to ~1500 characters.
"""

import hashlib
import math
import re

from sqlalchemy.orm import Session

from app.ai.adapters import AIProviderError, get_adapter
from app.models import (
    AttackTechnique,
    CweEntry,
    Embedding,
    KevEntry,
    Vulnerability,
    VulnerabilityRelationship,
)

LOCAL_FALLBACK_MODEL = "local-hash-384"
LOCAL_DIM = 384
MAX_CHUNK_CHARS = 1500

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def local_embed(texts: list[str]) -> list[list[float]]:
    """Deterministic hashing embedding (see module docstring).

    Each lower-cased word token is hashed (SHA-256) into one of 384
    buckets with a ±1 sign; the vector is then L2-normalised. The
    same text always produces the same vector; texts sharing words
    score higher under cosine similarity.
    """
    vectors: list[list[float]] = []
    for text in texts:
        vec = [0.0] * LOCAL_DIM
        for token in _TOKEN_RE.findall(text.lower()):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:4], "big") % LOCAL_DIM
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vec[bucket] += sign
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            vec = [v / norm for v in vec]
        vectors.append(vec)
    return vectors


def _embed_with_model(
    texts: list[str],
) -> tuple[list[list[float]], str]:
    """Embed ``texts`` via the provider, else the local fallback.

    Returns ``(vectors, model_name)``. A provider that has no
    embeddings API, or whose call fails, falls back to the local
    hashing embedding so indexing never breaks offline.
    """
    adapter = None
    try:
        adapter = get_adapter()
    except ValueError:
        adapter = None
    if adapter is not None:
        try:
            vectors = adapter.embed(texts)
            model = getattr(
                adapter, "embed_model", None
            ) or adapter.model
            return vectors, model
        except (AIProviderError, NotImplementedError):
            pass
    return local_embed(texts), LOCAL_FALLBACK_MODEL


def embed_texts(texts: list[str]) -> list[list[float]]:
    """Embed ``texts`` (provider when available, else local fallback)."""
    vectors, _model = _embed_with_model(texts)
    return vectors


def current_embedding_model() -> str:
    """Model name :func:`embed_texts` would use right now."""
    _vectors, model = _embed_with_model([""])
    return model


# ------------------------------------------------------------------
# Chunk building
# ------------------------------------------------------------------

def _cwe_ids_for_vulnerability(
    db: Session, vulnerability: Vulnerability
) -> list[str]:
    rels = (
        db.query(VulnerabilityRelationship)
        .filter(
            VulnerabilityRelationship.from_type == "vulnerability",
            VulnerabilityRelationship.from_id == vulnerability.id,
            VulnerabilityRelationship.relationship == "HAS_WEAKNESS",
            VulnerabilityRelationship.to_type == "cwe",
        )
        .all()
    )
    ids: list[str] = []
    for rel in rels:
        cwe = (
            db.query(CweEntry)
            .filter(CweEntry.id == rel.to_id)
            .first()
        )
        if cwe is not None:
            ids.append(cwe.cwe_id)
    return ids


def build_chunk_text(db: Session, entity_type: str, entity) -> str:
    """Build the embeddable chunk text for one entity (<=1500 chars)."""
    if entity_type == "vulnerability":
        cwe_ids = _cwe_ids_for_vulnerability(db, entity)
        cwe_part = (
            " CWE-" + ", CWE-".join(c.replace("CWE-", "") for c in cwe_ids)
            + "."
            if cwe_ids
            else ""
        )
        kev = (
            db.query(KevEntry)
            .filter(KevEntry.cve_id == entity.cve_id)
            .first()
        )
        score = (
            f"{float(entity.cvss_score):.1f}"
            if entity.cvss_score is not None
            else "not available"
        )
        severity = entity.severity or "unknown"
        chunk = (
            f"{entity.cve_id}. {entity.description or ''} "
            f"Severity {severity}, CVSS {score}.{cwe_part} "
            f"KEV: {'yes' if kev is not None else 'no'}."
        )
    elif entity_type == "cwe":
        chunk = (
            f"{entity.cwe_id} {entity.name}. "
            f"{entity.description or ''}"
        )
    elif entity_type == "attack_technique":
        chunk = (
            f"{entity.technique_id} {entity.name}. "
            f"{entity.tactic or ''}. {entity.description or ''}"
        )
    else:
        raise ValueError(f"Unknown entity_type: {entity_type!r}")
    return chunk[:MAX_CHUNK_CHARS]


_ENTITY_MODELS = {
    "vulnerability": Vulnerability,
    "cwe": CweEntry,
    "attack_technique": AttackTechnique,
}


def index_entity(
    db: Session, entity_type: str, entity_id
) -> Embedding:
    """Embed one entity and upsert its :class:`Embedding` row.

    One row per (entity_type, entity_id, model). Re-indexing the
    same entity with the same model updates the row in place.
    """
    model_cls = _ENTITY_MODELS.get(entity_type)
    if model_cls is None:
        raise ValueError(f"Unknown entity_type: {entity_type!r}")
    entity = (
        db.query(model_cls).filter(model_cls.id == entity_id).first()
    )
    if entity is None:
        raise ValueError(
            f"No {entity_type} with id {entity_id}"
        )
    chunk = build_chunk_text(db, entity_type, entity)
    vectors, model = _embed_with_model([chunk])
    existing = (
        db.query(Embedding)
        .filter(
            Embedding.entity_type == entity_type,
            Embedding.entity_id == entity_id,
            Embedding.model == model,
        )
        .first()
    )
    if existing is not None:
        existing.chunk_text = chunk
        existing.embedding = vectors[0]
        db.commit()
        db.refresh(existing)
        return existing
    row = Embedding(
        entity_type=entity_type,
        entity_id=entity_id,
        chunk_text=chunk,
        embedding=vectors[0],
        model=model,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


# ------------------------------------------------------------------
# Retrieval
# ------------------------------------------------------------------

def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length vectors (0.0 if either
    is a zero vector)."""
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _source_url_for(
    db: Session, entity_type: str, entity_id
) -> str | None:
    model_cls = _ENTITY_MODELS.get(entity_type)
    if model_cls is None:
        return None
    entity = (
        db.query(model_cls).filter(model_cls.id == entity_id).first()
    )
    return getattr(entity, "source_url", None) if entity else None


def retrieve(
    db: Session, query: str, top_k: int = 5
) -> list[dict]:
    """Rank stored embeddings by cosine similarity to ``query``.

    On Postgres the ranking uses pgvector ``<=>`` ordering; on
    SQLite (and any other dialect) cosine similarity is computed in
    Python. Returns ``[{entity_type, entity_id, chunk_text, score,
    source_url}]`` ordered by descending score. Returns ``[]`` when
    no embeddings exist — never pretends a search happened.
    """
    rows = db.query(Embedding).all()
    if not rows:
        return []

    # Embed the query with the same method the stored rows used:
    # use the most common stored model so query and stored vectors
    # live in the same space.
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.model] = counts.get(row.model, 0) + 1
    stored_model = max(counts, key=lambda m: counts[m])
    if stored_model == LOCAL_FALLBACK_MODEL:
        query_vec = local_embed([query])[0]
    else:
        try:
            adapter = get_adapter()
            if adapter is not None and (
                getattr(adapter, "embed_model", None) == stored_model
                or adapter.model == stored_model
            ):
                query_vec = adapter.embed([query])[0]
            else:
                query_vec = local_embed([query])[0]
        except (AIProviderError, NotImplementedError, ValueError):
            query_vec = local_embed([query])[0]

    # Postgres fast path (guarded: any failure falls back to Python).
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        try:
            ordered = (
                db.query(Embedding)
                .order_by(Embedding.embedding.cosine_distance(query_vec))
                .limit(top_k)
                .all()
            )
            results = []
            for row in ordered:
                vec = row.embedding
                score = (
                    cosine_similarity(query_vec, list(vec))
                    if vec is not None
                    else 0.0
                )
                results.append(
                    {
                        "entity_type": row.entity_type,
                        "entity_id": row.entity_id,
                        "chunk_text": row.chunk_text,
                        "score": float(score),
                        "source_url": _source_url_for(
                            db, row.entity_type, row.entity_id
                        ),
                    }
                )
            return results
        except Exception:
            pass  # fall through to the Python ranking below

    scored = []
    for row in rows:
        vec = row.embedding
        if vec is None:
            continue
        scored.append(
            (cosine_similarity(query_vec, list(vec)), row)
        )
    scored.sort(key=lambda item: item[0], reverse=True)
    results = []
    for score, row in scored[:top_k]:
        results.append(
            {
                "entity_type": row.entity_type,
                "entity_id": row.entity_id,
                "chunk_text": row.chunk_text,
                "score": float(score),
                "source_url": _source_url_for(
                    db, row.entity_type, row.entity_id
                ),
            }
        )
    return results
