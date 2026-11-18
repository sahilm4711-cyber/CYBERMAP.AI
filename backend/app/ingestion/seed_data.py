"""Clearly-labelled SEED dataset (Phase 4 fallback).

Used ONLY when live ingestion is impossible (all upstream sources
unreachable). Every record has ``source="seed"`` and a fixed
``source_updated_at``; this data is well-known public CVE information
included for local development only and must NEVER be described as
live intelligence. See ``app.ingestion.run.ingest_seed``.
"""

from __future__ import annotations

SEED_NOTE = (
    "SEED DATA — labelled fallback used only because live ingestion "
    "was unreachable; not live intelligence."
)

# Each entry is already in ``parse_nvd_record`` output shape:
# {"vulnerability": {...}, "references": [...], "products": [...],
# "cwe_ids": [...]}. Descriptions are short public summaries.
SEED_RECORDS: list[dict] = [
    {
        "vulnerability": {
            "cve_id": "CVE-2021-44228",
            "title": None,
            "description": (
                "Apache Log4j2 remote code execution via JNDI lookup "
                "in log messages (Log4Shell)."
            ),
            "cvss_score": 10.0,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "published_at": "2021-12-10T00:00:00+00:00",
            "last_modified_at": "2021-12-10T00:00:00+00:00",
            "source": "seed",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "source_updated_at": "2021-12-10T00:00:00+00:00",
        },
        "references": [
            {"url": "https://logging.apache.org/log4j/2.x/security.html",
             "source": "apache", "tags": ["Vendor Advisory"]}
        ],
        "products": [
            {"vendor": "apache", "product": "log4j", "version_start": "2.0",
             "version_end": "2.14.1", "version_range_text": ">= 2.0, <= 2.14.1"}
        ],
        "cwe_ids": ["CWE-917", "CWE-502", "CWE-20"],
    },
    {
        "vulnerability": {
            "cve_id": "CVE-2017-0144",
            "title": None,
            "description": (
                "Microsoft SMBv1 remote code execution (EternalBlue), "
                "used by the WannaCry ransomware worm."
            ),
            "cvss_score": 8.1,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "published_at": "2017-03-17T00:00:00+00:00",
            "last_modified_at": "2017-03-17T00:00:00+00:00",
            "source": "seed",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
            "source_updated_at": "2017-03-17T00:00:00+00:00",
        },
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144",
             "source": "microsoft", "tags": ["Vendor Advisory"]}
        ],
        "products": [
            {"vendor": "microsoft", "product": "windows", "version_start": None,
             "version_end": None, "version_range_text": None}
        ],
        "cwe_ids": ["CWE-119"],
    },
    {
        "vulnerability": {
            "cve_id": "CVE-2014-0160",
            "title": None,
            "description": (
                "OpenSSL TLS heartbeat extension buffer over-read "
                "(Heartbleed) leaking process memory."
            ),
            "cvss_score": 7.5,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "severity": "HIGH",
            "published_at": "2014-04-07T00:00:00+00:00",
            "last_modified_at": "2014-04-07T00:00:00+00:00",
            "source": "seed",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "source_updated_at": "2014-04-07T00:00:00+00:00",
        },
        "references": [
            {"url": "https://heartbleed.com/", "source": "heartbleed",
             "tags": ["Vendor Advisory"]}
        ],
        "products": [
            {"vendor": "openssl", "product": "openssl", "version_start": "1.0.1",
             "version_end": "1.0.1f", "version_range_text": ">= 1.0.1, <= 1.0.1f"}
        ],
        "cwe_ids": ["CWE-125"],
    },
    {
        "vulnerability": {
            "cve_id": "CVE-2021-34527",
            "title": None,
            "description": (
                "Windows Print Spooler remote code execution "
                "(PrintNightmare)."
            ),
            "cvss_score": 8.8,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "published_at": "2021-07-01T00:00:00+00:00",
            "last_modified_at": "2021-07-01T00:00:00+00:00",
            "source": "seed",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
            "source_updated_at": "2021-07-01T00:00:00+00:00",
        },
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
             "source": "microsoft", "tags": ["Vendor Advisory"]}
        ],
        "products": [
            {"vendor": "microsoft", "product": "windows",
             "version_start": None, "version_end": None,
             "version_range_text": None}
        ],
        "cwe_ids": ["CWE-269"],
    },
    {
        "vulnerability": {
            "cve_id": "CVE-2020-1472",
            "title": None,
            "description": (
                "Netlogon elevation of privilege (Zerologon) via a "
                "flawed AES-CFB8 initialization vector."
            ),
            "cvss_score": 10.0,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "published_at": "2020-08-17T00:00:00+00:00",
            "last_modified_at": "2020-08-17T00:00:00+00:00",
            "source": "seed",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
            "source_updated_at": "2020-08-17T00:00:00+00:00",
        },
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472",
             "source": "microsoft", "tags": ["Vendor Advisory"]}
        ],
        "products": [
            {"vendor": "microsoft", "product": "windows_server",
             "version_start": None, "version_end": None,
             "version_range_text": None}
        ],
        "cwe_ids": ["CWE-327"],
    },
    {
        "vulnerability": {
            "cve_id": "CVE-2019-0708",
            "title": None,
            "description": (
                "Remote Desktop Services remote code execution "
                "(BlueKeep) in Windows RDP."
            ),
            "cvss_score": 9.8,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "published_at": "2019-05-16T00:00:00+00:00",
            "last_modified_at": "2019-05-16T00:00:00+00:00",
            "source": "seed",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
            "source_updated_at": "2019-05-16T00:00:00+00:00",
        },
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
             "source": "microsoft", "tags": ["Vendor Advisory"]}
        ],
        "products": [
            {"vendor": "microsoft", "product": "windows",
             "version_start": None, "version_end": None,
             "version_range_text": None}
        ],
        "cwe_ids": ["CWE-119"],
    },
    {
        "vulnerability": {
            "cve_id": "CVE-2023-23397",
            "title": None,
            "description": (
                "Microsoft Outlook elevation of privilege via a crafted "
                "message that leaks NTLM hashes."
            ),
            "cvss_score": 9.8,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "published_at": "2023-03-14T00:00:00+00:00",
            "last_modified_at": "2023-03-14T00:00:00+00:00",
            "source": "seed",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-23397",
            "source_updated_at": "2023-03-14T00:00:00+00:00",
        },
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397",
             "source": "microsoft", "tags": ["Vendor Advisory"]}
        ],
        "products": [
            {"vendor": "microsoft", "product": "outlook",
             "version_start": None, "version_end": None,
             "version_range_text": None}
        ],
        "cwe_ids": ["CWE-200"],
    },
    {
        "vulnerability": {
            "cve_id": "CVE-2022-22965",
            "title": None,
            "description": (
                "Spring Framework remote code execution via data "
                "binding (Spring4Shell)."
            ),
            "cvss_score": 9.8,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "published_at": "2022-04-01T00:00:00+00:00",
            "last_modified_at": "2022-04-01T00:00:00+00:00",
            "source": "seed",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
            "source_updated_at": "2022-04-01T00:00:00+00:00",
        },
        "references": [
            {"url": "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
             "source": "vmware", "tags": ["Vendor Advisory"]}
        ],
        "products": [
            {"vendor": "vmware", "product": "spring_framework",
             "version_start": "5.3.0", "version_end": "5.3.17",
             "version_range_text": ">= 5.3.0, <= 5.3.17"}
        ],
        "cwe_ids": ["CWE-502"],
    },
    {
        "vulnerability": {
            "cve_id": "CVE-2021-26855",
            "title": None,
            "description": (
                "Microsoft Exchange Server server-side request forgery "
                "(ProxyLogon) chained for remote code execution."
            ),
            "cvss_score": 9.8,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "published_at": "2021-03-02T00:00:00+00:00",
            "last_modified_at": "2021-03-02T00:00:00+00:00",
            "source": "seed",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855",
            "source_updated_at": "2021-03-02T00:00:00+00:00",
        },
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855",
             "source": "microsoft", "tags": ["Vendor Advisory"]}
        ],
        "products": [
            {"vendor": "microsoft", "product": "exchange_server",
             "version_start": None, "version_end": None,
             "version_range_text": None}
        ],
        "cwe_ids": ["CWE-918"],
    },
    {
        "vulnerability": {
            "cve_id": "CVE-2020-0601",
            "title": None,
            "description": (
                "Windows CryptoAPI spoofing vulnerability (CurveBall) "
                "in ECC certificate validation."
            ),
            "cvss_score": 8.1,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            "severity": "HIGH",
            "published_at": "2020-01-14T00:00:00+00:00",
            "last_modified_at": "2020-01-14T00:00:00+00:00",
            "source": "seed",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-0601",
            "source_updated_at": "2020-01-14T00:00:00+00:00",
        },
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0601",
             "source": "microsoft", "tags": ["Vendor Advisory"]}
        ],
        "products": [
            {"vendor": "microsoft", "product": "windows",
             "version_start": None, "version_end": None,
             "version_range_text": None}
        ],
        "cwe_ids": ["CWE-295"],
    },
]
