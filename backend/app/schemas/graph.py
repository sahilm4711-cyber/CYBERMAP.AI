"""Pydantic schemas for the attack knowledge graph API — Phase 7.

Every edge carries ``source`` and ``confidence`` (DATABASE.md §2.9):
edges copied from ``vulnerability_relationships`` keep their stored
values; edges computed from rows that exist (e.g. CVE -> affected
product) are ``source="nvd"``, ``confidence="verified"``; anything
inferred is ``source="inferred"``, ``confidence="inferred"``.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NodeType = Literal[
    "vulnerability", "cwe", "attack_technique", "product", "vendor"
]


class GraphNode(BaseModel):
    """One entity in the graph.

    ``id`` is a prefixed key: ``vulnerability:<uuid>``,
    ``cwe:<uuid>``, ``attack_technique:<uuid>``,
    ``product:<vendor>::<product>``, ``vendor:<vendor>``.
    """

    id: str
    type: NodeType
    label: str
    subtitle: str | None = None
    detail_url: str | None = None


class GraphEdge(BaseModel):
    """One relationship. ``from`` is the source node id.

    ``from_node`` serializes as ``from`` (a Python keyword, so the
    attribute has a different name).
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    from_node: str = Field(
        serialization_alias="from", validation_alias="from"
    )
    to: str
    relationship: str
    source: str
    confidence: str


class GraphResponse(BaseModel):
    """A graph (or a subgraph) plus pagination info.

    ``limit`` caps nodes per response (default 50). When more nodes
    were discovered than returned, ``has_more`` is true and
    ``total_nodes`` / ``total_edges`` count everything discovered
    before the cap, so the caller can ask for a bigger ``limit`` or
    expand one node at a time.
    """

    seed: str | None = None
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    has_more: bool = False
    total_nodes: int = 0
    total_edges: int = 0
    note: str | None = None


class NodeDetailResponse(BaseModel):
    """Full record fields for one entity + its direct neighbours."""

    id: str
    type: NodeType
    label: str
    subtitle: str | None = None
    detail_url: str | None = None
    fields: dict = Field(default_factory=dict)
    neighbours: list[GraphNode] = Field(default_factory=list)
    neighbour_edges: list[GraphEdge] = Field(default_factory=list)


class SearchResult(BaseModel):
    id: str
    type: NodeType
    label: str
    subtitle: str | None = None


class SearchResponse(BaseModel):
    query: str
    results: list[SearchResult] = Field(default_factory=list)


class ExpandRequest(BaseModel):
    node_type: NodeType
    node_id: str = Field(min_length=1, max_length=512)


class ExpandResponse(BaseModel):
    node_id: str
    node_type: NodeType
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    has_more: bool = False
    total_nodes: int = 0
    total_edges: int = 0


class CweTechniqueItem(BaseModel):
    id: str
    technique_id: str
    name: str
    tactic: str | None = None
    relationship: str
    source: str
    confidence: str


class CweTechniquesResponse(BaseModel):
    cwe_id: str
    techniques: list[CweTechniqueItem] = Field(default_factory=list)
