"""Attack knowledge graph API tests (Phase 7).

The graph router is NOT registered in ``app/main.py`` (the
coordinator registers routers), so these tests include it on the
test app explicitly — the same router object the coordinator will
register (same convention as the Phase 6 AI tests).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1 import graph as graph_router
from app.models import (
    AffectedProduct,
    AttackTechnique,
    CweEntry,
    Vulnerability,
    VulnerabilityRelationship,
)
from tests.conftest import login_user, register_user


@pytest.fixture()
def graph_client(app_with_db):
    app, _ = app_with_db
    if not any(
        getattr(r, "path", "").startswith("/api/v1/graph")
        for r in app.routes
    ):
        app.include_router(graph_router.router)
    return TestClient(app)


@pytest.fixture()
def authed(graph_client):
    register_user(graph_client, "alice")
    login_user(graph_client, "alice")
    return graph_client


@pytest.fixture()
def seeded(db_session: Session):
    """2 CVEs sharing one CWE, 1 technique, 2 products, stored rels."""
    cwe = CweEntry(
        cwe_id="CWE-79",
        name="Improper Neutralization of Input During Web Page Generation",
        description="Cross-site scripting weakness.",
    )
    tech = AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        description="Adversaries abuse PowerShell.",
        tactic="Execution",
        mitigations=[{"id": "M1049", "name": "Antivirus/Antimalware"}],
    )
    vuln_a = Vulnerability(
        cve_id="CVE-2024-11111",
        description="Reflected XSS in the search page.",
        cvss_score=6.1,
        severity="MEDIUM",
    )
    vuln_b = Vulnerability(
        cve_id="CVE-2024-22222",
        description="Stored XSS in comments.",
        cvss_score=7.2,
        severity="HIGH",
    )
    db_session.add_all([cwe, tech, vuln_a, vuln_b])
    db_session.flush()
    cwe_unlinked = CweEntry(
        cwe_id="CWE-89",
        name="Improper Neutralization of Special Elements used in an SQL Command",
        description="SQL injection weakness.",
    )
    db_session.add(cwe_unlinked)
    db_session.flush()
    db_session.add_all(
        [
            VulnerabilityRelationship(
                from_type="vulnerability",
                from_id=vuln_a.id,
                to_type="cwe",
                to_id=cwe.id,
                relationship="HAS_WEAKNESS",
                source="nvd",
                confidence="verified",
            ),
            VulnerabilityRelationship(
                from_type="vulnerability",
                from_id=vuln_b.id,
                to_type="cwe",
                to_id=cwe.id,
                relationship="HAS_WEAKNESS",
                source="nvd",
                confidence="verified",
            ),
            VulnerabilityRelationship(
                from_type="cwe",
                from_id=cwe.id,
                to_type="attack_technique",
                to_id=tech.id,
                relationship="EXPLOITS",
                source="mitre-attack",
                confidence="verified",
            ),
        ]
    )
    db_session.add_all(
        [
            AffectedProduct(
                vulnerability_id=vuln_a.id,
                vendor="acme",
                product="widget",
                version_range_text="<= 2.0",
            ),
            AffectedProduct(
                vulnerability_id=vuln_a.id,
                vendor="acme",
                product="gadget",
                version_range_text=">= 1.0",
            ),
        ]
    )
    db_session.commit()
    return {
        "cwe": cwe,
        "cwe_unlinked": cwe_unlinked,
        "tech": tech,
        "vuln_a": vuln_a,
        "vuln_b": vuln_b,
    }


def _assert_edges_have_provenance(payload: dict) -> None:
    for edge in payload.get("edges", []) + payload.get(
        "neighbour_edges", []
    ):
        assert edge["source"], f"edge {edge['id']} has empty source"
        assert edge["confidence"], (
            f"edge {edge['id']} has empty confidence"
        )


def _assert_no_duplicate_edges(payload: dict) -> None:
    keys = [
        (e["from"], e["to"], e["relationship"])
        for e in payload["edges"]
    ]
    assert len(keys) == len(set(keys)), "duplicate edges returned"
    ids = [n["id"] for n in payload["nodes"]]
    assert len(ids) == len(set(ids)), "duplicate nodes returned"


def test_graph_depth1_contains_cve_cwe_products(
    authed, seeded
):
    resp = authed.get(
        "/api/v1/graph", params={"seed_cve": "CVE-2024-11111"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    node_ids = {n["id"] for n in data["nodes"]}
    labels = {(n["type"], n["label"]) for n in data["nodes"]}
    assert ("vulnerability", "CVE-2024-11111") in labels
    assert ("cwe", "CWE-79") in labels
    assert ("product", "widget") in labels
    assert ("product", "gadget") in labels
    assert ("vendor", "acme") in labels
    # Technique is linked to the CWE, so it appears at depth 1 too.
    assert ("attack_technique", "T1059.001") in labels
    assert data["seed"] == "CVE-2024-11111"
    assert data["has_more"] is False
    _assert_no_duplicate_edges(data)
    _assert_edges_have_provenance(data)
    # CVE B shares the CWE but is only one hop away via the CWE:
    # depth 1 must NOT include it.
    assert ("vulnerability", "CVE-2024-22222") not in labels
    # Every node id is unique and prefixed by type.
    assert all(n["id"].startswith(n["type"] + ":") for n in data["nodes"])
    assert node_ids  # noqa: B018 - set is non-empty


def test_graph_depth2_includes_cve_sharing_cwe(authed, seeded):
    resp = authed.get(
        "/api/v1/graph",
        params={"seed_cve": "CVE-2024-11111", "depth": 2},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    labels = {(n["type"], n["label"]) for n in data["nodes"]}
    assert ("vulnerability", "CVE-2024-22222") in labels
    _assert_no_duplicate_edges(data)
    _assert_edges_have_provenance(data)


def test_graph_limit_reports_has_more(authed, seeded):
    resp = authed.get(
        "/api/v1/graph",
        params={"seed_cve": "CVE-2024-11111", "depth": 2, "limit": 2},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["nodes"]) == 2
    assert data["has_more"] is True
    assert data["total_nodes"] > 2
    # Edges only reference nodes that were actually returned.
    kept = {n["id"] for n in data["nodes"]}
    assert all(
        e["from"] in kept and e["to"] in kept for e in data["edges"]
    )


def test_graph_unknown_seed_404(authed, seeded):
    resp = authed.get(
        "/api/v1/graph", params={"seed_cve": "CVE-1999-99999"}
    )
    assert resp.status_code == 404


def test_node_detail_returns_neighbours(authed, seeded):
    cwe = seeded["cwe"]
    resp = authed.get(f"/api/v1/graph/node/cwe/{cwe.id}")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["type"] == "cwe"
    assert data["label"] == "CWE-79"
    assert "Cross-site scripting" in data["fields"]["description"]
    neighbour_labels = {
        (n["type"], n["label"]) for n in data["neighbours"]
    }
    assert ("vulnerability", "CVE-2024-11111") in neighbour_labels
    assert ("vulnerability", "CVE-2024-22222") in neighbour_labels
    assert ("attack_technique", "T1059.001") in neighbour_labels
    assert len(data["neighbours"]) <= 20
    _assert_edges_have_provenance(data)


def test_node_detail_technique_includes_mitigations(
    authed, seeded
):
    tech = seeded["tech"]
    resp = authed.get(
        f"/api/v1/graph/node/attack_technique/{tech.id}"
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["fields"]["mitigations"] == [
        {"id": "M1049", "name": "Antivirus/Antimalware"}
    ]


def test_node_detail_unknown_404(authed, seeded):
    resp = authed.get(
        "/api/v1/graph/node/cwe/00000000-0000-0000-0000-000000000000"
    )
    assert resp.status_code == 404
    resp = authed.get("/api/v1/graph/node/bogus/CWE-79")
    assert resp.status_code == 404


def test_search_finds_by_cve_id_and_cwe_name(authed, seeded):
    resp = authed.get(
        "/api/v1/graph/search", params={"q": "CVE-2024-11111"}
    )
    assert resp.status_code == 200, resp.text
    assert any(
        r["type"] == "vulnerability" and r["label"] == "CVE-2024-11111"
        for r in resp.json()["results"]
    )
    resp = authed.get(
        "/api/v1/graph/search", params={"q": "Neutralization"}
    )
    assert resp.status_code == 200, resp.text
    assert any(
        r["type"] == "cwe" and r["label"] == "CWE-79"
        for r in resp.json()["results"]
    )
    resp = authed.get(
        "/api/v1/graph/search", params={"q": "widget"}
    )
    assert any(
        r["type"] == "product" and r["label"] == "widget"
        for r in resp.json()["results"]
    )


def test_expand_cwe_node_returns_neighbours(authed, seeded):
    cwe = seeded["cwe"]
    resp = authed.post(
        "/api/v1/graph/expand",
        json={"node_type": "cwe", "node_id": f"cwe:{cwe.id}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    labels = {(n["type"], n["label"]) for n in data["nodes"]}
    assert ("vulnerability", "CVE-2024-11111") in labels
    assert ("vulnerability", "CVE-2024-22222") in labels
    assert ("attack_technique", "T1059.001") in labels
    _assert_edges_have_provenance(data)
    keys = [
        (e["from"], e["to"], e["relationship"])
        for e in data["edges"]
    ]
    assert len(keys) == len(set(keys))


def test_expand_unknown_node_404(authed, seeded):
    resp = authed.post(
        "/api/v1/graph/expand",
        json={
            "node_type": "cwe",
            "node_id": "00000000-0000-0000-0000-000000000000",
        },
    )
    assert resp.status_code == 404


def test_cwe_techniques_lists_stored_links(authed, seeded):
    resp = authed.get("/api/v1/graph/cwe/CWE-79/techniques")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["cwe_id"] == "CWE-79"
    assert len(data["techniques"]) == 1
    tech = data["techniques"][0]
    assert tech["technique_id"] == "T1059.001"
    assert tech["source"] == "mitre-attack"
    assert tech["confidence"] == "verified"


def test_cwe_techniques_empty_list_is_valid(authed, seeded):
    # CWE-89 is indexed but has no stored technique links: an empty
    # list is a valid answer, not an error.
    resp = authed.get("/api/v1/graph/cwe/CWE-89/techniques")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"cwe_id": "CWE-89", "techniques": []}
    # Unknown CWE is a real 404.
    resp = authed.get("/api/v1/graph/cwe/CWE-9999/techniques")
    assert resp.status_code == 404


def test_graph_endpoints_require_auth(graph_client, seeded):
    for method, url, kwargs in [
        ("GET", "/api/v1/graph", {"params": {"seed_cve": "CVE-2024-11111"}}),
        ("GET", "/api/v1/graph/search", {"params": {"q": "CVE"}}),
        ("GET", "/api/v1/graph/cwe/CWE-79/techniques", {}),
        ("GET", "/api/v1/graph/node/cwe/CWE-79", {}),
        (
            "POST",
            "/api/v1/graph/expand",
            {"json": {"node_type": "cwe", "node_id": "CWE-79"}},
        ),
    ]:
        resp = graph_client.request(method, url, **kwargs)
        assert resp.status_code == 401, (method, url, resp.text)
