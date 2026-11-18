"""Parser tests (Phase 4) — mocked data only, never live APIs."""

from datetime import date

import httpx
import pytest

from app.ingestion import connectors
from app.integrations import epss as epss_client
from app.integrations import kev as kev_client
from app.integrations import mitre as mitre_client
from app.integrations import nvd as nvd_client
from app.integrations.common import IngestionHTTPError
from tests.ingestion_fixtures import (
    ATTACK_BUNDLE,
    CWE_XML_SAMPLE,
    EPSS_RESPONSE,
    KEV_RECORD,
    NVD_FULL_RECORD,
    NVD_NO_CVSS_RECORD,
    NVD_V2_ONLY_RECORD,
)


# --------------------------------------------------------------------- NVD

def test_nvd_full_record_parses_everything():
    parsed = connectors.parse_nvd_record(NVD_FULL_RECORD)
    vuln = parsed["vulnerability"]
    assert vuln["cve_id"] == "CVE-2024-12345"
    assert vuln["description"].startswith("A test vulnerability")
    assert vuln["cvss_score"] == 9.8
    assert vuln["cvss_version"] == "3.1"
    assert vuln["cvss_vector"].startswith("CVSS:3.1/")
    assert vuln["severity"] == "CRITICAL"
    assert vuln["source"] == "nvd"
    assert vuln["source_updated_at"] is not None
    # References.
    assert len(parsed["references"]) == 2
    assert parsed["references"][0]["url"] == "https://example.com/advisory"
    assert parsed["references"][0]["tags"] == ["Vendor Advisory"]
    # Products: vulnerable CPEs only; the vulnerable=False entry excluded.
    products = parsed["products"]
    assert len(products) == 2
    first = products[0]
    assert first["vendor"] == "example"
    assert first["product"] == "examplelib"
    assert first["version_start"] == "1.0.0"
    assert first["version_end"] == "2.3.4"
    assert ">= 1.0.0" in first["version_range_text"]
    assert "< 2.3.4" in first["version_range_text"]
    # Concrete version without a range.
    assert products[1]["product"] == "otherlib"
    assert products[1]["version_start"] == "1.2.3"
    # CWE ids, kept in CWE-NNN format.
    assert parsed["cwe_ids"] == ["CWE-79", "CWE-89"]


def test_nvd_duplicate_reference_url_deduped():
    record = {
        "cve": {
            "id": "CVE-2024-55555",
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Dup refs."}],
            "references": [
                {"url": "https://example.com/same", "source": "a",
                 "tags": ["Exploit"]},
                {"url": "https://example.com/same", "source": "b",
                 "tags": ["Patch"]},
            ],
        }
    }
    parsed = connectors.parse_nvd_record(record)
    assert len(parsed["references"]) == 1
    assert parsed["references"][0]["source"] == "a"


def test_nvd_record_without_cvss_has_null_scores():
    parsed = connectors.parse_nvd_record(NVD_NO_CVSS_RECORD)
    vuln = parsed["vulnerability"]
    assert vuln["cvss_score"] is None
    assert vuln["cvss_version"] is None
    assert vuln["cvss_vector"] is None
    assert vuln["severity"] is None
    assert vuln["description"] == "A vulnerability with no CVSS data yet."


def test_nvd_record_with_only_cvss_v2_uses_v2():
    parsed = connectors.parse_nvd_record(NVD_V2_ONLY_RECORD)
    vuln = parsed["vulnerability"]
    assert vuln["cvss_score"] == 7.5
    assert vuln["cvss_version"] == "2.0"
    assert vuln["severity"] == "HIGH"


def test_nvd_client_paginates_and_uses_mock_transport():
    page1 = {
        "resultsPerPage": 2, "startIndex": 0, "totalResults": 3,
        "vulnerabilities": [NVD_FULL_RECORD, NVD_NO_CVSS_RECORD],
    }
    page2 = {
        "resultsPerPage": 2, "startIndex": 2, "totalResults": 3,
        "vulnerabilities": [NVD_V2_ONLY_RECORD],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params.get("startIndex", "0"))
        assert "lastModStartDate" in request.url.params
        return httpx.Response(200, json=page1 if start == 0 else page2)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    nvd = nvd_client.NvdClient(client=client, sleep=lambda _: None)
    records = nvd.fetch_incremental(days=7)
    assert len(records) == 3
    assert records[2]["cve"]["id"] == "CVE-2010-12345"


def test_nvd_client_retries_429_then_succeeds():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(
            200,
            json={"resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
                  "vulnerabilities": [NVD_NO_CVSS_RECORD]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    nvd = nvd_client.NvdClient(client=client, sleep=lambda _: None)
    records = nvd.fetch_incremental(days=7)
    assert calls["n"] == 2
    assert len(records) == 1


def test_nvd_client_persistent_500_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"message": "boom"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    nvd = nvd_client.NvdClient(client=client, sleep=lambda _: None)
    with pytest.raises(IngestionHTTPError):
        nvd.fetch_incremental(days=7)


# --------------------------------------------------------------------- KEV

def test_kev_parser():
    parsed = connectors.parse_kev_record(KEV_RECORD)
    assert parsed["cve_id"] == "CVE-2024-12345"
    assert parsed["vendor_project"] == "Example"
    assert parsed["product"] == "ExampleLib"
    assert parsed["date_added"] == date(2024, 2, 10)
    assert parsed["due_date"] == date(2024, 3, 2)
    assert parsed["ransomware_use"] == "Known"


def test_kev_client_parses_catalog_via_mock():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"vulnerabilities": [KEV_RECORD], "count": 1}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    records = kev_client.fetch_kev(client=client, sleep=lambda _: None)
    assert records == [KEV_RECORD]


# -------------------------------------------------------------------- EPSS

def test_epss_parser_scores_and_model_date():
    records, model_date = None, None
    parsed = [
        connectors.parse_epss_record(item, date(2024, 2, 15))
        for item in EPSS_RESPONSE["data"]
    ]
    assert parsed[0]["cve_id"] == "CVE-2024-12345"
    assert parsed[0]["epss_score"] == pytest.approx(0.91234)
    assert parsed[0]["percentile"] == pytest.approx(0.98765)
    assert parsed[0]["model_date"] == date(2024, 2, 15)
    assert parsed[1]["epss_score"] == pytest.approx(0.00123)


def test_epss_client_chunks_and_returns_model_date():
    seen_params: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_params.append(request.url.params["cve"])
        return httpx.Response(200, json=EPSS_RESPONSE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    records, model_date = epss_client.fetch_epss_scores(
        ["CVE-2024-12345", "CVE-2024-99999"],
        client=client,
        sleep=lambda _: None,
    )
    assert model_date == date(2024, 2, 15)
    assert len(records) == 2
    assert seen_params == ["CVE-2024-12345,CVE-2024-99999"]


def test_epss_client_reads_per_record_date_when_no_top_level_model_date():
    """The live API carries "date" per record, not top-level "model_date"."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"status": "OK", "data": [
                {"cve": "CVE-2024-12345", "epss": "0.5",
                 "percentile": "0.9", "date": "2024-02-15"},
            ]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    records, model_date = epss_client.fetch_epss_scores(
        ["CVE-2024-12345"], client=client, sleep=lambda _: None,
    )
    assert model_date == date(2024, 2, 15)
    parsed = connectors.parse_epss_record(records[0], model_date)
    assert parsed["model_date"] == date(2024, 2, 15)
    # Per-record date also works when the caller passes no model date.
    assert connectors.parse_epss_record(records[0], None)["model_date"] == date(2024, 2, 15)


def test_epss_client_chunks_at_100():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.params["cve"])
        return httpx.Response(
            200, json={"status": "OK", "model_date": "2024-02-15", "data": []}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    epss_client.fetch_epss_scores(
        [f"CVE-2024-{i:05d}" for i in range(250)],
        client=client,
        sleep=lambda _: None,
    )
    assert len(calls) == 3
    assert len(calls[0].split(",")) == 100
    assert len(calls[2].split(",")) == 50


# ------------------------------------------------------------------- MITRE

def test_mitre_attack_parser_technique_id_name_tactic():
    techniques = mitre_client.parse_attack_techniques(ATTACK_BUNDLE)
    # Revoked technique + non-attack-pattern object are skipped.
    assert len(techniques) == 1
    tech = techniques[0]
    assert tech["technique_id"] == "T1059.001"
    assert tech["name"] == "PowerShell"
    assert tech["tactic"] == "Execution"
    assert tech["platforms"] == ["Windows"]
    assert tech["detection"] == "Monitor PowerShell logs."
    assert tech["source_url"] == "https://attack.mitre.org/techniques/T1059/001/"


def test_cwe_xml_parser_small_sample():
    entries = mitre_client.parse_cwe_xml(CWE_XML_SAMPLE.encode("utf-8"))
    assert len(entries) == 2
    assert entries[0]["cwe_id"] == "CWE-79"
    assert entries[0]["name"].startswith("Improper Neutralization of Input")
    assert entries[0]["description"] == "Cross-site scripting description."
    assert entries[0]["extended_description"] == "Extended XSS description."
    assert entries[1]["cwe_id"] == "CWE-89"
    assert entries[1]["extended_description"] is None
