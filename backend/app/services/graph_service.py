"""Attack knowledge graph service — Phase 7.

Builds graphs from the Phase 3/4 data:

* CVE -> CWE edges come from stored ``vulnerability_relationships``
  rows (``HAS_WEAKNESS``, created by ingestion from NVD weakness
  data — see ``app/ingestion/run.py``). Their stored ``source`` /
  ``confidence`` are kept verbatim.
* CWE -> ATT&CK technique edges exist ONLY where a stored
  relationship row links them. There is no reliable text match:
  a technique whose description happens to mention a CWE number is
  NOT a link, so no such edge is ever invented. When none exist the
  graph says so instead of showing techniques.
* CVE -> affected product / vendor edges are computed from
  ``affected_products`` rows, which exist because NVD listed the
  product for that CVE — so they are ``source="nvd"``,
  ``confidence="verified"``.
* Mitigations are not graph nodes (they are not in the §2.9 node
  enum). They ride along in a technique node's detail fields, taken
  from ``attack_techniques.mitigations`` JSON when present.

Node ids are prefixed keys (``vulnerability:<uuid>``,
``cwe:<uuid>``, ``attack_technique:<uuid>``,
``product:<vendor>::<product>``, ``vendor:<vendor>``) so ids are
unique across types and round-trip through the API unchanged.
"""

from __future__ import annotations

import uuid

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models import (
    AffectedProduct,
    AttackTechnique,
    CweEntry,
    Vulnerability,
    VulnerabilityRelationship,
)

# Per-expansion caps (before the response-level ``limit`` applies).
CWE_OTHER_CVES_CAP = 10
PRODUCT_OTHER_CVES_CAP = 10
NEIGHBOURS_CAP = 20

NODE_TYPES = (
    "vulnerability",
    "cwe",
    "attack_technique",
    "product",
    "vendor",
)


# ------------------------------------------------------------------ nodes

def node_id(node_type: str, key: str) -> str:
    return f"{node_type}:{key}"


def vulnerability_node(vuln: Vulnerability) -> dict:
    return {
        "id": node_id("vulnerability", str(vuln.id)),
        "type": "vulnerability",
        "label": vuln.cve_id,
        "subtitle": vuln.severity
        or (f"CVSS {vuln.cvss_score}" if vuln.cvss_score is not None else None),
        "detail_url": f"/vulnerability/{vuln.cve_id}",
    }


def cwe_node(cwe: CweEntry) -> dict:
    return {
        "id": node_id("cwe", str(cwe.id)),
        "type": "cwe",
        "label": cwe.cwe_id,
        "subtitle": cwe.name,
        "detail_url": None,
    }


def technique_node(tech: AttackTechnique) -> dict:
    return {
        "id": node_id("attack_technique", str(tech.id)),
        "type": "attack_technique",
        "label": tech.technique_id,
        "subtitle": tech.name,
        "detail_url": None,
    }


def product_node(vendor: str | None, product: str | None) -> dict:
    return {
        "id": node_id("product", f"{vendor or ''}::{product or ''}"),
        "type": "product",
        "label": product or "unknown product",
        "subtitle": vendor,
        "detail_url": None,
    }


def vendor_node(vendor: str) -> dict:
    return {
        "id": node_id("vendor", vendor),
        "type": "vendor",
        "label": vendor,
        "subtitle": None,
        "detail_url": None,
    }


# ------------------------------------------------------- stored-rel edges

def _stored_edge(rel: VulnerabilityRelationship) -> dict:
    """A relationship-table row -> an edge, keeping its provenance."""
    return {
        "id": f"rel:{rel.id}",
        "from": _rel_node_id(rel.from_type, rel.from_id),
        "to": _rel_node_id(rel.to_type, rel.to_id),
        "relationship": rel.relationship,
        "source": rel.source or "inferred",
        "confidence": rel.confidence or "inferred",
    }


def _rel_node_id(node_type: str, row_id: uuid.UUID) -> str:
    """Node id for a relationship endpoint.

    Products/vendors have no own table, so a stored edge pointing
    at them cannot happen today; fall back to the raw UUID.
    """
    if node_type in ("vulnerability", "cwe", "attack_technique"):
        return node_id(node_type, str(row_id))
    return node_id(node_type, str(row_id))


def _stored_edges_for(
    db: Session, node_type: str, row_id: uuid.UUID
) -> tuple[list[dict], list[dict]]:
    """Edges touching one entity, in both directions.

    Returns (edges, neighbour node dicts) for stored relationships
    only — product/vendor endpoints are skipped because those rows
    have no table to resolve against.
    """
    rels = (
        db.query(VulnerabilityRelationship)
        .filter(
            or_(
                (VulnerabilityRelationship.from_type == node_type)
                & (VulnerabilityRelationship.from_id == row_id),
                (VulnerabilityRelationship.to_type == node_type)
                & (VulnerabilityRelationship.to_id == row_id),
            )
        )
        .all()
    )
    edges: list[dict] = []
    nodes: list[dict] = []
    for rel in rels:
        if rel.from_type == node_type and rel.from_id == row_id:
            other_type, other_id = rel.to_type, rel.to_id
        else:
            other_type, other_id = rel.from_type, rel.from_id
        other = _load_entity(db, other_type, str(other_id))
        if other is None:
            continue
        edges.append(_stored_edge(rel))
        nodes.append(other[1])
    return edges, nodes


def _load_entity(
    db: Session, node_type: str, key: str
) -> tuple[object, dict] | None:
    """Load one entity by type + key (UUID or natural id).

    Returns ``(row, node dict)`` or ``None``. Products/vendors are
    resolved from ``affected_products`` rows, not a table of their own.
    """
    if node_type == "vulnerability":
        row = _by_uuid_or_natural(
            db, Vulnerability, key, Vulnerability.cve_id
        )
        return (row, vulnerability_node(row)) if row else None
    if node_type == "cwe":
        row = _by_uuid_or_natural(db, CweEntry, key, CweEntry.cwe_id)
        return (row, cwe_node(row)) if row else None
    if node_type == "attack_technique":
        row = _by_uuid_or_natural(
            db, AttackTechnique, key, AttackTechnique.technique_id
        )
        return (row, technique_node(row)) if row else None
    if node_type == "product":
        vendor, _, product = key.partition("::")
        if not product:
            return None
        exists = (
            db.query(AffectedProduct)
            .filter(
                AffectedProduct.vendor == (vendor or None),
                AffectedProduct.product == product,
            )
            .first()
        )
        if exists is None:
            return None
        return (exists, product_node(vendor or None, product))
    if node_type == "vendor":
        exists = (
            db.query(AffectedProduct)
            .filter(AffectedProduct.vendor == key)
            .first()
        )
        if exists is None:
            return None
        return (exists, vendor_node(key))
    return None


def _by_uuid_or_natural(db, model, key: str, natural_col):
    """Look a row up by UUID first, then by its natural id."""
    try:
        parsed = uuid.UUID(key)
    except (ValueError, AttributeError, TypeError):
        parsed = None
    if parsed is not None:
        row = db.query(model).filter(model.id == parsed).first()
        if row is not None:
            return row
    return db.query(model).filter(natural_col == key).first()


def node_exists(db: Session, node_type: str, key: str) -> bool:
    """True when the entity behind ``node_type`` + ``key`` exists."""
    return _load_entity(db, node_type, key) is not None


def parse_node_id(node_type: str, node_id_value: str) -> str:
    """Accept a bare key or a prefixed ``type:key`` id; return the key."""
    prefix = f"{node_type}:"
    if node_id_value.startswith(prefix):
        return node_id_value[len(prefix):]
    return node_id_value


# -------------------------------------------------------------- neighbours

def neighbours_of(
    db: Session, node_type: str, key: str
) -> tuple[list[dict], list[dict]]:
    """Direct neighbours of one entity: (nodes, edges), deduped.

    Combines stored relationship edges with computed edges from
    ``affected_products`` rows. Caps apply per expansion kind so one
    popular CWE or product cannot flood the graph.
    """
    entity = _load_entity(db, node_type, key)
    if entity is None:
        return [], []
    row, _ = entity
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def _add_node(node: dict) -> None:
        nodes.setdefault(node["id"], node)

    def _add_edge(edge: dict) -> None:
        edges.setdefault(
            (edge["from"], edge["to"], edge["relationship"]), edge
        )

    if node_type == "vulnerability":
        vuln = row
        stored_edges, stored_nodes = _stored_edges_for(
            db, "vulnerability", vuln.id
        )
        for edge in stored_edges:
            _add_edge(edge)
        for node in stored_nodes:
            _add_node(node)
        _add_product_neighbours(db, vuln, nodes, edges)
    elif node_type == "cwe":
        cwe = row
        stored_edges, stored_nodes = _stored_edges_for(db, "cwe", cwe.id)
        # Cap the other CVEs sharing this CWE (depth-2 fan-out).
        cve_count = 0
        for edge, node in zip(stored_edges, stored_nodes):
            if node["type"] == "vulnerability":
                cve_count += 1
                if cve_count > CWE_OTHER_CVES_CAP:
                    continue
            _add_edge(edge)
            _add_node(node)
    elif node_type == "attack_technique":
        tech = row
        stored_edges, stored_nodes = _stored_edges_for(
            db, "attack_technique", tech.id
        )
        for edge in stored_edges:
            _add_edge(edge)
        for node in stored_nodes:
            _add_node(node)
    elif node_type == "product":
        vendor, _, product = key.partition("::")
        if vendor:
            nodes.setdefault(
                node_id("vendor", vendor), vendor_node(vendor)
            )
        _add_product_cve_neighbours(
            db, vendor or None, product, nodes, edges
        )
    elif node_type == "vendor":
        products = (
            db.query(AffectedProduct.vendor, AffectedProduct.product)
            .filter(AffectedProduct.vendor == key)
            .distinct()
            .limit(NEIGHBOURS_CAP)
            .all()
        )
        for vendor, product in products:
            if not product:
                continue
            _add_node(product_node(vendor, product))
            _add_edge(
                {
                    "id": f"provides:{vendor}::{product}",
                    "from": node_id("vendor", vendor),
                    "to": node_id(
                        "product", f"{vendor or ''}::{product or ''}"
                    ),
                    "relationship": "PROVIDES",
                    "source": "nvd",
                    "confidence": "verified",
                }
            )

    return list(nodes.values()), list(edges.values())


def _add_product_neighbours(db, vuln, nodes, edges) -> None:
    """CVE -> affected products (+ their vendors), from NVD rows."""
    products = (
        db.query(AffectedProduct)
        .filter(AffectedProduct.vulnerability_id == vuln.id)
        .limit(NEIGHBOURS_CAP)
        .all()
    )
    for prod in products:
        if not prod.product:
            continue
        nodes.setdefault(
            node_id(
                "product", f"{prod.vendor or ''}::{prod.product or ''}"
            ),
            product_node(prod.vendor, prod.product),
        )
        edges.setdefault(
            (
                node_id("vulnerability", str(vuln.id)),
                node_id(
                    "product", f"{prod.vendor or ''}::{prod.product or ''}"
                ),
                "AFFECTS",
            ),
            {
                "id": f"affects:{vuln.id}:{prod.id}",
                "from": node_id("vulnerability", str(vuln.id)),
                "to": node_id(
                    "product", f"{prod.vendor or ''}::{prod.product or ''}"
                ),
                "relationship": "AFFECTS",
                "source": "nvd",
                "confidence": "verified",
            },
        )
        if prod.vendor:
            nodes.setdefault(
                node_id("vendor", prod.vendor), vendor_node(prod.vendor)
            )
            edges.setdefault(
                (
                    node_id("vendor", prod.vendor),
                    node_id(
                        "product",
                        f"{prod.vendor or ''}::{prod.product or ''}",
                    ),
                    "PROVIDES",
                ),
                {
                    "id": f"provides:{prod.vendor}::{prod.product}",
                    "from": node_id("vendor", prod.vendor),
                    "to": node_id(
                        "product",
                        f"{prod.vendor or ''}::{prod.product or ''}",
                    ),
                    "relationship": "PROVIDES",
                    "source": "nvd",
                    "confidence": "verified",
                },
            )


def _add_product_cve_neighbours(
    db, vendor, product, nodes, edges
) -> None:
    """Other CVEs affecting the same vendor/product (depth-2 fan-out)."""
    if not product:
        return
    rows = (
        db.query(AffectedProduct)
        .filter(
            AffectedProduct.vendor == vendor,
            AffectedProduct.product == product,
        )
        .limit(PRODUCT_OTHER_CVES_CAP)
        .all()
    )
    for prod in rows:
        vuln = (
            db.query(Vulnerability)
            .filter(Vulnerability.id == prod.vulnerability_id)
            .first()
        )
        if vuln is None:
            continue
        nodes.setdefault(
            node_id("vulnerability", str(vuln.id)),
            vulnerability_node(vuln),
        )
        edges.setdefault(
            (
                node_id("vulnerability", str(vuln.id)),
                node_id("product", f"{vendor or ''}::{product or ''}"),
                "AFFECTS",
            ),
            {
                "id": f"affects:{vuln.id}:{prod.id}",
                "from": node_id("vulnerability", str(vuln.id)),
                "to": node_id(
                    "product", f"{vendor or ''}::{product or ''}"
                ),
                "relationship": "AFFECTS",
                "source": "nvd",
                "confidence": "verified",
            },
        )
    # Vendor -> product edge (canonical direction).
    if vendor:
        edges.setdefault(
            (
                node_id("vendor", vendor),
                node_id("product", f"{vendor or ''}::{product or ''}"),
                "PROVIDES",
            ),
            {
                "id": f"provides:{vendor}::{product}",
                "from": node_id("vendor", vendor),
                "to": node_id(
                    "product", f"{vendor or ''}::{product or ''}"
                ),
                "relationship": "PROVIDES",
                "source": "nvd",
                "confidence": "verified",
            },
        )


# ------------------------------------------------------------ graph build

def build_graph(
    db: Session, seed_cve: str, depth: int = 1, limit: int = 50
) -> dict | None:
    """Breadth-first graph centred on one CVE.

    Returns ``None`` when the seed CVE is not indexed. Depth 1 is
    the CVE's CWEs, techniques (stored links only), products and
    vendors; depth 2 expands each depth-1 node one more hop (other
    CVEs sharing a CWE, capped at 10 per CWE).
    """
    seed = (
        db.query(Vulnerability)
        .filter(Vulnerability.cve_id == seed_cve.strip().upper())
        .first()
    )
    if seed is None:
        seed = (
            db.query(Vulnerability)
            .filter(Vulnerability.cve_id == seed_cve.strip())
            .first()
        )
    if seed is None:
        return None

    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    seed_node = vulnerability_node(seed)
    nodes[seed_node["id"]] = seed_node

    frontier = [("vulnerability", str(seed.id))]
    for level in range(depth):
        next_frontier: list[tuple[str, str]] = []
        for node_type, key in frontier:
            n_nodes, n_edges = neighbours_of(db, node_type, key)
            for node in n_nodes:
                if node["id"] not in nodes:
                    nodes[node["id"]] = node
                    next_frontier.append(_node_type_key(node["id"]))
            for edge in n_edges:
                edges.setdefault(
                    (edge["from"], edge["to"], edge["relationship"]),
                    edge,
                )
        if level == 0:
            # Depth 1 also includes the techniques linked to the
            # seed's CWEs (stored CWE -> technique rows only). Other
            # CVEs sharing a CWE stay a depth-2 expansion.
            for node in list(nodes.values()):
                if node["type"] != "cwe":
                    continue
                t_nodes, t_edges = neighbours_of(
                    db, "cwe", node["id"].partition(":")[2]
                )
                for t_node in t_nodes:
                    if t_node["type"] != "attack_technique":
                        continue
                    if t_node["id"] not in nodes:
                        nodes[t_node["id"]] = t_node
                        next_frontier.append(
                            _node_type_key(t_node["id"])
                        )
                for t_edge in t_edges:
                    if (
                        t_edge["from"] in nodes
                        and t_edge["to"] in nodes
                        and (
                            nodes[t_edge["from"]]["type"]
                            == "attack_technique"
                            or nodes[t_edge["to"]]["type"]
                            == "attack_technique"
                        )
                    ):
                        edges.setdefault(
                            (
                                t_edge["from"],
                                t_edge["to"],
                                t_edge["relationship"],
                            ),
                            t_edge,
                        )
        frontier = next_frontier
        if not frontier:
            break

    total_nodes = len(nodes)
    total_edges = len(edges)
    has_more = total_nodes > limit
    kept_nodes = dict(list(nodes.items())[:limit])
    kept_edges = [
        e
        for e in edges.values()
        if e["from"] in kept_nodes and e["to"] in kept_nodes
    ]
    note = None
    if not any(n["type"] == "attack_technique" for n in kept_nodes.values()):
        note = (
            "No linked techniques indexed for this CVE's CWE(s): "
            "CWE -> technique edges only exist where a stored "
            "relationship row links them, and none was found."
        )
    return {
        "seed": seed.cve_id,
        "nodes": list(kept_nodes.values()),
        "edges": kept_edges,
        "has_more": has_more,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "note": note,
    }


def _node_type_key(prefixed_id: str) -> tuple[str, str]:
    node_type, _, key = prefixed_id.partition(":")
    return node_type, key


# ------------------------------------------------------------ node detail

def node_detail(
    db: Session, node_type: str, key: str
) -> dict | None:
    """Full record fields for one entity + direct neighbours (<= 20)."""
    entity = _load_entity(db, node_type, key)
    if entity is None:
        return None
    row, node = entity
    fields: dict = {}
    if node_type == "vulnerability":
        fields = {
            "cve_id": row.cve_id,
            "description": row.description,
            "severity": row.severity,
            "cvss_score": float(row.cvss_score)
            if row.cvss_score is not None
            else None,
            "cvss_version": row.cvss_version,
            "cvss_vector": row.cvss_vector,
            "published_at": row.published_at.isoformat()
            if row.published_at
            else None,
            "source": row.source,
            "source_url": row.source_url,
        }
    elif node_type == "cwe":
        fields = {
            "cwe_id": row.cwe_id,
            "name": row.name,
            "description": row.description,
            "extended_description": row.extended_description,
            "category": row.category,
            "source": row.source,
            "source_url": row.source_url,
        }
    elif node_type == "attack_technique":
        fields = {
            "technique_id": row.technique_id,
            "name": row.name,
            "description": row.description,
            "tactic": row.tactic,
            "platforms": row.platforms,
            "detection": row.detection,
            "mitigations": row.mitigations,
            "source": row.source,
            "source_url": row.source_url,
        }
    elif node_type == "product":
        vendor, _, product = key.partition("::")
        fields = {
            "vendor": vendor or None,
            "product": product,
            "affected_cves": _product_cve_count(db, vendor or None, product),
        }
    elif node_type == "vendor":
        fields = {
            "vendor": key,
            "product_count": _vendor_product_count(db, key),
        }

    n_nodes, n_edges = neighbours_of(db, node_type, key)
    return {
        **node,
        "fields": fields,
        "neighbours": n_nodes[:NEIGHBOURS_CAP],
        "neighbour_edges": [
            e
            for e in n_edges
            if e["from"] in {n["id"] for n in n_nodes[:NEIGHBOURS_CAP]}
            or e["to"] in {n["id"] for n in n_nodes[:NEIGHBOURS_CAP]}
        ][:NEIGHBOURS_CAP],
    }


def _product_cve_count(db, vendor, product) -> int:
    return (
        db.query(AffectedProduct)
        .filter(
            AffectedProduct.vendor == vendor,
            AffectedProduct.product == product,
        )
        .count()
    )


def _vendor_product_count(db, vendor) -> int:
    return (
        db.query(AffectedProduct.vendor, AffectedProduct.product)
        .filter(AffectedProduct.vendor == vendor)
        .distinct()
        .count()
    )


# ------------------------------------------------------------------ search

def search_entities(db: Session, query: str, limit: int = 20) -> list[dict]:
    """Search CVE / CWE / technique / product by label or ID."""
    q = f"%{query.strip()}%"
    results: list[dict] = []

    for vuln in (
        db.query(Vulnerability)
        .filter(
            or_(
                Vulnerability.cve_id.ilike(q),
                Vulnerability.description.ilike(q),
            )
        )
        .limit(limit)
        .all()
    ):
        node = vulnerability_node(vuln)
        results.append(
            {
                "id": node["id"],
                "type": "vulnerability",
                "label": vuln.cve_id,
                "subtitle": vuln.severity,
            }
        )
    for cwe in (
        db.query(CweEntry)
        .filter(
            or_(CweEntry.cwe_id.ilike(q), CweEntry.name.ilike(q))
        )
        .limit(limit)
        .all()
    ):
        node = cwe_node(cwe)
        results.append(
            {
                "id": node["id"],
                "type": "cwe",
                "label": cwe.cwe_id,
                "subtitle": cwe.name,
            }
        )
    for tech in (
        db.query(AttackTechnique)
        .filter(
            or_(
                AttackTechnique.technique_id.ilike(q),
                AttackTechnique.name.ilike(q),
            )
        )
        .limit(limit)
        .all()
    ):
        node = technique_node(tech)
        results.append(
            {
                "id": node["id"],
                "type": "attack_technique",
                "label": tech.technique_id,
                "subtitle": tech.name,
            }
        )
    for vendor, product in (
        db.query(AffectedProduct.vendor, AffectedProduct.product)
        .filter(
            or_(
                AffectedProduct.vendor.ilike(q),
                AffectedProduct.product.ilike(q),
            )
        )
        .distinct()
        .limit(limit)
        .all()
    ):
        if not product:
            continue
        node = product_node(vendor, product)
        results.append(
            {
                "id": node["id"],
                "type": "product",
                "label": product,
                "subtitle": vendor,
            }
        )
    return results[:limit]


# ------------------------------------------------------- CWE -> techniques

def cwe_techniques(db: Session, cwe_id: str) -> dict | None:
    """Techniques linked to a CWE via stored relationship rows.

    Returns ``None`` when the CWE is not indexed; an empty
    ``techniques`` list is a valid answer (no stored link), not an
    error.
    """
    normalized = cwe_id.strip().upper()
    if not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    cwe = (
        db.query(CweEntry).filter(CweEntry.cwe_id == normalized).first()
    )
    if cwe is None:
        return None
    rels = (
        db.query(VulnerabilityRelationship)
        .filter(
            VulnerabilityRelationship.from_type == "cwe",
            VulnerabilityRelationship.from_id == cwe.id,
            VulnerabilityRelationship.to_type == "attack_technique",
        )
        .all()
    )
    techniques: list[dict] = []
    for rel in rels:
        tech = (
            db.query(AttackTechnique)
            .filter(AttackTechnique.id == rel.to_id)
            .first()
        )
        if tech is None:
            continue
        techniques.append(
            {
                "id": node_id("attack_technique", str(tech.id)),
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactic": tech.tactic,
                "relationship": rel.relationship,
                "source": rel.source or "inferred",
                "confidence": rel.confidence or "inferred",
            }
        )
    return {"cwe_id": cwe.cwe_id, "techniques": techniques}
