"""Attack knowledge graph API — ``/api/v1/graph`` (Phase 7).

NOTE: this router is intentionally NOT registered in
``app/main.py`` yet — the coordinator registers routers (same
convention as the Phase 6 AI router). All endpoints require auth.

Graph semantics live in ``app/services/graph_service.py``: CVE ->
CWE edges come from stored ``vulnerability_relationships`` rows,
CWE -> technique edges only where a stored row links them, and
CVE -> product / vendor edges from ``affected_products`` rows.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import User
from app.schemas.graph import (
    CweTechniquesResponse,
    ExpandRequest,
    ExpandResponse,
    GraphResponse,
    NodeDetailResponse,
    SearchResponse,
)
from app.security.csrf import verify_origin
from app.security.dependencies import get_current_user
from app.services import graph_service

router = APIRouter(
    prefix="/api/v1/graph",
    tags=["graph"],
    dependencies=[Depends(verify_origin)],
)


@router.get("", response_model=GraphResponse)
def get_graph(
    seed_cve: str = Query(..., min_length=1, max_length=32),
    depth: int = Query(1, ge=1, le=2),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> GraphResponse:
    """Graph centred on one CVE (depth 1 or 2, capped at ``limit`` nodes)."""
    result = graph_service.build_graph(db, seed_cve, depth=depth, limit=limit)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE not indexed: {seed_cve}",
        )
    return GraphResponse(**result)


@router.get("/search", response_model=SearchResponse)
def search_graph(
    q: str = Query(..., min_length=1, max_length=128),
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> SearchResponse:
    """Search entities by label/ID across CVE, CWE, technique, product."""
    return SearchResponse(
        query=q, results=graph_service.search_entities(db, q, limit=limit)
    )


@router.get(
    "/cwe/{cwe_id}/techniques", response_model=CweTechniquesResponse
)
def cwe_techniques(
    cwe_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CweTechniquesResponse:
    """Techniques linked to a CWE via stored relationships.

    An empty list is a valid answer (no stored link), not an error;
    an unknown CWE id is 404.
    """
    result = graph_service.cwe_techniques(db, cwe_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CWE not indexed: {cwe_id}",
        )
    return CweTechniquesResponse(**result)


@router.get("/node/{node_type}/{node_id}", response_model=NodeDetailResponse)
def get_node(
    node_type: str,
    node_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> NodeDetailResponse:
    """Full record fields for one entity + its direct neighbours."""
    if node_type not in graph_service.NODE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown node type: {node_type}",
        )
    key = graph_service.parse_node_id(node_type, node_id)
    result = graph_service.node_detail(db, node_type, key)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node not found: {node_type}/{node_id}",
        )
    return NodeDetailResponse(**result)


@router.post("/expand", response_model=ExpandResponse)
def expand_node(
    payload: ExpandRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ExpandResponse:
    """Neighbours of one node (for progressive graph expansion)."""
    key = graph_service.parse_node_id(
        payload.node_type, payload.node_id
    )
    if not graph_service.node_exists(db, payload.node_type, key):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node not found: {payload.node_type}/{payload.node_id}",
        )
    nodes, edges = graph_service.neighbours_of(
        db, payload.node_type, key
    )
    return ExpandResponse(
        node_id=payload.node_id,
        node_type=payload.node_type,
        nodes=nodes,
        edges=edges,
        has_more=False,
        total_nodes=len(nodes),
        total_edges=len(edges),
    )
