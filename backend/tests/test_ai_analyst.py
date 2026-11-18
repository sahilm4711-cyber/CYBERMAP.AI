"""Analyst tests (Phase 6): fallback analysis, mocked provider
analysis, provider-error fallback, and the 10-section structure."""

import json
from datetime import date

import pytest
from sqlalchemy.orm import Session

from app.ai.adapters import AIProviderError
from app.ai.analyst import (
    SECTION_KEYS,
    analyze_vulnerability,
    build_rule_based_analysis,
)
from app.models import (
    AffectedProduct,
    CweEntry,
    EpssScore,
    KevEntry,
    Vulnerability,
    VulnerabilityReference,
    VulnerabilityRelationship,
)
from app.services import auth_service
from app.services.seed import get_role
from app.models import User
import app.ai.analyst as analyst_module


def _make_user(db_session: Session, username="analyst-user") -> User:
    role = get_role(db_session, "user")
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash="hashed",
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture()
def full_vuln(db_session: Session) -> Vulnerability:
    v = Vulnerability(
        cve_id="CVE-2024-22222",
        description=(
            "A remote code execution flaw in the widget service "
            "allows unauthenticated attackers to run arbitrary code."
        ),
        cvss_score=9.8,
        cvss_version="3.1",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="CRITICAL",
        source="nvd",
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-22222",
    )
    db_session.add(v)
    db_session.commit()
    cwe = CweEntry(
        cwe_id="CWE-94",
        name="Code Injection",
        description="Improper control of code generation.",
        source="mitre-cwe",
        source_url="https://cwe.mitre.org/data/definitions/94.html",
    )
    db_session.add(cwe)
    db_session.commit()
    db_session.add(
        VulnerabilityRelationship(
            from_type="vulnerability",
            from_id=v.id,
            to_type="cwe",
            to_id=cwe.id,
            relationship="HAS_WEAKNESS",
            source="nvd",
        )
    )
    db_session.add(
        VulnerabilityReference(
            vulnerability_id=v.id,
            url="https://example.com/advisory-1",
            source="vendor",
        )
    )
    db_session.add(
        AffectedProduct(
            vulnerability_id=v.id,
            vendor="Acme",
            product="Widget",
            version_range_text="Widget < 2.0",
        )
    )
    db_session.add(
        KevEntry(
            cve_id="CVE-2024-22222",
            vendor_project="Acme",
            product="Widget",
            due_date=date(2024, 12, 1),
            required_action="Apply the vendor patch.",
            source="cisa-kev",
        )
    )
    db_session.add(
        EpssScore(
            cve_id="CVE-2024-22222",
            epss_score=0.91234,
            percentile=0.98765,
            model_date=date(2024, 11, 1),
        )
    )
    db_session.commit()
    return v


@pytest.fixture()
def no_cvss_vuln(db_session: Session) -> Vulnerability:
    v = Vulnerability(
        cve_id="CVE-2024-33333",
        description="A flaw with no published CVSS score yet.",
        severity=None,
        source="nvd",
    )
    db_session.add(v)
    db_session.commit()
    return v


def test_fallback_analysis_has_all_10_sections(db_session, full_vuln):
    sections = build_rule_based_analysis(
        db_session, full_vuln, "simple"
    )
    assert sorted(sections.keys()) == sorted(SECTION_KEYS)
    # Numbers come from the DB record, not invented.
    assert "9.8" in sections["risk_assessment"]
    assert "CRITICAL" in sections["risk_assessment"]
    assert "0.91234" in sections["risk_assessment"]
    assert "CWE-94" in sections["root_cause"]
    assert "Acme Widget" in sections["affected_components"]
    assert sections["confidence_and_limitations"]["confidence"] == "low"
    assert (
        "rule-based summary — no AI provider configured"
        in sections["confidence_and_limitations"]["limitations"]
    )
    # References cite the record's URLs.
    urls = [r["url"] for r in sections["references"]]
    assert "https://example.com/advisory-1" in urls
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-22222" in urls


def test_fallback_missing_cvss_never_invents_score(
    db_session, no_cvss_vuln
):
    sections = build_rule_based_analysis(
        db_session, no_cvss_vuln, "simple"
    )
    assert "No CVSS score" in sections["risk_assessment"]
    assert "0.0" not in sections["risk_assessment"]
    assert "Not available in the indexed record" in sections["root_cause"]
    assert "Not available in the indexed record" in sections[
        "affected_components"
    ]


def test_analyze_vulnerability_fallback_envelope(
    db_session, full_vuln
):
    user = _make_user(db_session)
    result = analyze_vulnerability(
        db_session, "CVE-2024-22222", "advanced", user
    )
    assert result["ai_mode"] == "fallback"
    assert result["model"] is None
    assert result["cve_id"] == "CVE-2024-22222"
    assert sorted(result["analysis"].keys()) == sorted(SECTION_KEYS)
    assert result["citations"][0]["cve_id"] == "CVE-2024-22222"
    # Saved to saved_analyses.
    from app.models import SavedAnalysis

    rows = (
        db_session.query(SavedAnalysis)
        .filter(SavedAnalysis.user_id == user.id)
        .all()
    )
    assert len(rows) == 1
    assert rows[0].ai_mode == "fallback"
    assert rows[0].analysis_type == "advanced"


def test_analyze_unknown_cve_raises(db_session):
    from app.ai.analyst import VulnerabilityNotFoundError

    with pytest.raises(VulnerabilityNotFoundError):
        analyze_vulnerability(db_session, "CVE-1999-99999", "simple")


def test_analyze_bad_type_raises(db_session, full_vuln):
    from app.ai.analyst import InvalidAnalysisTypeError

    with pytest.raises(InvalidAnalysisTypeError):
        analyze_vulnerability(
            db_session, "CVE-2024-22222", "not-a-type"
        )


class _FakeProvider:
    """Mocked provider returning a canned 10-section JSON reply."""

    model = "gpt-4o-mini"
    embed_model = None

    def __init__(self, reply: str | None = None, error: Exception | None = None):
        self._reply = reply
        self._error = error

    def chat(self, messages, **kwargs):
        if self._error is not None:
            raise self._error
        return self._reply

    def embed(self, texts):
        raise NotImplementedError


def _provider_reply() -> str:
    sections = {
        "executive_summary": "Provider summary.",
        "technical_explanation": "Provider technical.",
        "root_cause": "Provider root cause.",
        "potential_impact": "Provider impact.",
        "affected_components": "Provider components.",
        "risk_assessment": "Provider risk.",
        "defensive_verification": "Provider verification.",
        "remediation": "Provider remediation.",
        "references": [
            {"label": "vendor", "url": "https://example.com/x"}
        ],
        "confidence_and_limitations": {
            "confidence": "medium",
            "limitations": ["Provider-generated."],
        },
    }
    return json.dumps(sections)


def test_provider_analysis_uses_provider_content(
    db_session, full_vuln, monkeypatch
):
    monkeypatch.setattr(
        analyst_module,
        "get_adapter",
        lambda: _FakeProvider(reply=_provider_reply()),
    )
    user = _make_user(db_session)
    result = analyze_vulnerability(
        db_session, "CVE-2024-22222", "simple", user
    )
    assert result["ai_mode"] == "provider"
    assert result["model"] == "gpt-4o-mini"
    assert result["analysis"]["executive_summary"] == "Provider summary."
    assert (
        result["analysis"]["confidence_and_limitations"]["confidence"]
        == "medium"
    )


def test_provider_error_falls_back_to_rule_based(
    db_session, full_vuln, monkeypatch
):
    monkeypatch.setattr(
        analyst_module,
        "get_adapter",
        lambda: _FakeProvider(error=AIProviderError("boom")),
    )
    user = _make_user(db_session)
    result = analyze_vulnerability(
        db_session, "CVE-2024-22222", "simple", user
    )
    assert result["ai_mode"] == "fallback"
    assert result["fallback_reason"] is not None
    assert "9.8" in result["analysis"]["risk_assessment"]


def test_provider_unparseable_reply_falls_back(
    db_session, full_vuln, monkeypatch
):
    monkeypatch.setattr(
        analyst_module,
        "get_adapter",
        lambda: _FakeProvider(reply="this is not json at all"),
    )
    user = _make_user(db_session)
    result = analyze_vulnerability(
        db_session, "CVE-2024-22222", "simple", user
    )
    assert result["ai_mode"] == "fallback"
    assert sorted(result["analysis"].keys()) == sorted(SECTION_KEYS)
