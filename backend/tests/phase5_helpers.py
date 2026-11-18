"""Shared seed data for Phase 5 tests (not a test module itself).

Six CVEs with varied severity / CVSS / EPSS / KEV / CWE so every
dashboard count, filter and sort can be asserted exactly.
"""

from datetime import date, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    AffectedProduct,
    CweEntry,
    DataSource,
    EpssScore,
    IngestionJob,
    KevEntry,
    Vulnerability,
    VulnerabilityReference,
    VulnerabilityRelationship,
)
from tests.conftest import login_user, register_user


def seed_phase5_data(db: Session) -> dict:
    """Seed the temp DB; returns the created objects by CVE id."""
    cwe79 = CweEntry(
        cwe_id="CWE-79",
        name="Cross-site Scripting",
        description="Improper neutralization of input during web page generation.",
    )
    cwe89 = CweEntry(
        cwe_id="CWE-89",
        name="SQL Injection",
        description="Improper neutralization of special elements in SQL commands.",
    )
    cwe20 = CweEntry(
        cwe_id="CWE-20",
        name="Improper Input Validation",
        description="The product receives input but does not validate it.",
    )
    db.add_all([cwe79, cwe89, cwe20])
    db.flush()

    specs = [
        # cve_id, severity, cvss, published, title, description, cwe
        (
            "CVE-2024-0001",
            "CRITICAL",
            9.8,
            datetime(2024, 1, 10, 12, 0),
            "Remote code execution in widget service",
            "Remote code execution in the widget service allows an unauthenticated attacker to run arbitrary code.",
            cwe79,
        ),
        (
            "CVE-2024-0002",
            "HIGH",
            8.8,
            datetime(2024, 2, 5, 12, 0),
            "SQL injection in login form",
            "SQL injection in the login form lets an attacker dump the user table.",
            cwe89,
        ),
        (
            "CVE-2024-0003",
            "MEDIUM",
            5.5,
            datetime(2024, 3, 1, 12, 0),
            "Cross-site scripting via search",
            "Cross-site scripting via the search box lets an attacker run scripts in a victim browser.",
            cwe79,
        ),
        (
            "CVE-2024-0004",
            "LOW",
            2.5,
            datetime(2024, 1, 20, 12, 0),
            "Information disclosure in logs",
            "Information disclosure in application logs exposes session tokens.",
            cwe20,
        ),
        (
            "CVE-2023-9999",
            "HIGH",
            7.5,
            datetime(2023, 6, 1, 12, 0),
            "Buffer overflow in parser",
            "Buffer overflow in the file parser allows memory corruption.",
            cwe20,
        ),
        (
            "CVE-2024-0005",
            "NONE",
            0.0,
            datetime(2024, 4, 1, 12, 0),
            "Documentation typo",
            "A documentation typo in the user guide. No security impact.",
            None,
        ),
    ]
    vulns: dict[str, Vulnerability] = {}
    for cve_id, severity, cvss, published, title, desc, cwe in specs:
        vuln = Vulnerability(
            cve_id=cve_id,
            title=title,
            description=desc,
            cvss_score=cvss,
            cvss_version="3.1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity=severity,
            published_at=published,
            last_modified_at=published,
            source="nvd",
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        )
        db.add(vuln)
        db.flush()
        vulns[cve_id] = vuln
        if cwe is not None:
            db.add(
                VulnerabilityRelationship(
                    from_type="vulnerability",
                    from_id=vuln.id,
                    to_type="cwe",
                    to_id=cwe.id,
                    relationship="HAS_WEAKNESS",
                    source="nvd",
                    confidence="verified",
                )
            )

    db.add_all(
        [
            AffectedProduct(
                vulnerability_id=vulns["CVE-2024-0001"].id,
                vendor="acme",
                product="widget",
                version_start="1.0",
                version_end="2.3",
                version_range_text="1.0 - 2.3",
            ),
            AffectedProduct(
                vulnerability_id=vulns["CVE-2024-0002"].id,
                vendor="acme",
                product="login",
                version_range_text="all versions",
            ),
        ]
    )
    db.add(
        VulnerabilityReference(
            vulnerability_id=vulns["CVE-2024-0001"].id,
            url="https://example.com/advisory-0001",
            source="vendor",
        )
    )

    db.add_all(
        [
            KevEntry(
                cve_id="CVE-2024-0001",
                vulnerability_id=vulns["CVE-2024-0001"].id,
                vendor_project="Acme",
                product="Widget",
                vulnerability_name="Acme Widget RCE",
                date_added=date(2024, 1, 15),
                due_date=date(2024, 2, 1),
                short_description="Acme Widget RCE exploited in the wild.",
                required_action="Apply the vendor patch immediately.",
                ransomware_use="Known",
            ),
            KevEntry(
                cve_id="CVE-2024-0004",
                vulnerability_id=vulns["CVE-2024-0004"].id,
                vendor_project="Acme",
                product="Logs",
                vulnerability_name="Acme Logs information disclosure",
                date_added=date(2024, 1, 25),
                due_date=date(2024, 2, 15),
                short_description="Log disclosure exploited in the wild.",
                required_action="Rotate exposed tokens and patch.",
                ransomware_use="Unknown",
            ),
        ]
    )

    db.add_all(
        [
            EpssScore(
                cve_id="CVE-2024-0001",
                vulnerability_id=vulns["CVE-2024-0001"].id,
                epss_score=0.9,
                percentile=0.99,
                model_date=date(2024, 4, 2),
            ),
            EpssScore(
                cve_id="CVE-2024-0002",
                vulnerability_id=vulns["CVE-2024-0002"].id,
                epss_score=0.5,
                percentile=0.95,
                model_date=date(2024, 4, 2),
            ),
            EpssScore(
                cve_id="CVE-2024-0003",
                vulnerability_id=vulns["CVE-2024-0003"].id,
                epss_score=0.05,
                percentile=0.5,
                model_date=date(2024, 4, 2),
            ),
            EpssScore(
                cve_id="CVE-2024-0004",
                vulnerability_id=vulns["CVE-2024-0004"].id,
                epss_score=0.01,
                percentile=0.2,
                model_date=date(2024, 4, 2),
            ),
            EpssScore(
                cve_id="CVE-2023-9999",
                vulnerability_id=vulns["CVE-2023-9999"].id,
                epss_score=0.75,
                percentile=0.98,
                model_date=date(2024, 4, 2),
            ),
        ]
    )

    nvd = db.query(DataSource).filter(DataSource.name == "nvd").first()
    if nvd is not None:
        nvd.last_sync_at = datetime(2024, 4, 2, 10, 0)
        nvd.last_sync_status = "success"
        db.add(
            IngestionJob(
                source_id=nvd.id,
                started_at=datetime(2024, 4, 2, 10, 0),
                finished_at=datetime(2024, 4, 2, 10, 5),
                status="success",
                records_fetched=6,
                records_created=6,
                triggered_by="scheduler",
            )
        )
    db.commit()
    return vulns


def authed_client(client: TestClient, username: str = "alice") -> TestClient:
    """Register + log in a user on the given client (sets the cookie)."""
    register_user(client, username)
    login_user(client, username)
    return client
