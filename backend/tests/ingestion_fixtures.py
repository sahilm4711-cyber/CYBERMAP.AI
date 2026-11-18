"""Small recorded-style fixtures for the Phase 4 ingestion tests.

These are hand-built miniature records shaped like the real NVD /
KEV / EPSS / MITRE payloads — tests NEVER hit live APIs.
"""

from __future__ import annotations

NVD_FULL_RECORD = {
    "cve": {
        "id": "CVE-2024-12345",
        "sourceIdentifier": "security@example.com",
        "published": "2024-01-15T10:00:00.000",
        "lastModified": "2024-02-01T12:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "en", "value": "A test vulnerability in ExampleLib allows remote code execution."},
            {"lang": "es", "value": "Una vulnerabilidad de prueba."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.9,
                }
            ],
            "cvssMetricV2": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Secondary",
                    "cvssData": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    },
                }
            ],
        },
        "weaknesses": [
            {"source": "nvd@nist.gov", "type": "Primary",
             "description": [{"lang": "en", "value": "CWE-79"}]},
            {"source": "nvd@nist.gov", "type": "Secondary",
             "description": [{"lang": "en", "value": "CWE-89"}]},
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:example:examplelib:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0.0",
                                "versionEndExcluding": "2.3.4",
                                "matchCriteriaId": "11111111-1111-1111-1111-111111111111",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:example:otherlib:1.2.3:*:*:*:*:*:*:*",
                                "matchCriteriaId": "22222222-2222-2222-2222-222222222222",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:a:example:notvuln:9.9.9:*:*:*:*:*:*:*",
                                "matchCriteriaId": "33333333-3333-3333-3333-333333333333",
                            },
                        ],
                    }
                ]
            }
        ],
        "references": [
            {"url": "https://example.com/advisory", "source": "example",
             "tags": ["Vendor Advisory"]},
            {"url": "https://example.com/poc", "source": "example",
             "tags": ["Exploit"]},
        ],
    }
}

NVD_NO_CVSS_RECORD = {
    "cve": {
        "id": "CVE-2024-99999",
        "published": "2024-03-01T00:00:00.000",
        "lastModified": "2024-03-02T00:00:00.000",
        "descriptions": [
            {"lang": "en", "value": "A vulnerability with no CVSS data yet."}
        ],
        "weaknesses": [],
        "configurations": [],
        "references": [],
    }
}

NVD_V2_ONLY_RECORD = {
    "cve": {
        "id": "CVE-2010-12345",
        "published": "2010-05-01T00:00:00.000",
        "lastModified": "2010-06-01T00:00:00.000",
        "descriptions": [
            {"lang": "en", "value": "An old vulnerability scored only under CVSS 2.0."}
        ],
        "metrics": {
            "cvssMetricV2": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    },
                }
            ]
        },
        "weaknesses": [],
        "configurations": [],
        "references": [],
    }
}

KEV_RECORD = {
    "cveID": "CVE-2024-12345",
    "vendorProject": "Example",
    "product": "ExampleLib",
    "vulnerabilityName": "ExampleLib Remote Code Execution",
    "dateAdded": "2024-02-10",
    "dueDate": "2024-03-02",
    "shortDescription": "ExampleLib RCE exploited in the wild.",
    "requiredAction": "Apply the vendor update.",
    "knownRansomwareCampaignUse": "Known",
}

EPSS_RESPONSE = {
    "status": "OK",
    "model_date": "2024-02-15",
    "data": [
        {"cve": "CVE-2024-12345", "epss": "0.91234", "percentile": "0.98765"},
        {"cve": "CVE-2024-99999", "epss": "0.00123", "percentile": "0.12345"},
    ],
}

ATTACK_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--11111111-1111-1111-1111-111111111111",
            "name": "PowerShell",
            "description": "Adversaries may abuse PowerShell to execute code.",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
            "x_mitre_platforms": ["Windows"],
            "x_mitre_detection": "Monitor PowerShell logs.",
            "external_references": [
                {"source_name": "mitre-attack",
                 "external_id": "T1059.001",
                 "url": "https://attack.mitre.org/techniques/T1059/001/"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--22222222-2222-2222-2222-222222222222",
            "name": "Revoked Technique",
            "description": "Should be skipped.",
            "revoked": True,
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999.999",
                 "url": "https://attack.mitre.org/techniques/T9999/999/"}
            ],
        },
        {"type": "malware", "id": "malware--33333333-3333-3333-3333-333333333333",
         "name": "Not a technique"},
    ],
}

CWE_XML_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="4.14" Date="2024-01-01">
  <Weaknesses>
    <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" Abstraction="Base" Status="Stable">
      <Description>Cross-site scripting description.</Description>
      <Extended_Description>Extended XSS description.</Extended_Description>
    </Weakness>
    <Weakness ID="89" Name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')" Abstraction="Base" Status="Stable">
      <Description>SQL injection description.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""
