from collector.app.enrichment import parse_nvd


def test_parse_nvd_prefers_cvss_v31_metric():
    payload = {
        "cve": {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "baseSeverity": "HIGH",
                        "cvssData": {
                            "baseScore": 8.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        },
                    }
                ]
            }
        }
    }

    parsed = parse_nvd(payload)

    assert parsed["cvss_score"] == 8.8
    assert parsed["cvss_vector"].startswith("CVSS:3.1")
    assert parsed["severity"] == "HIGH"
    assert parsed["epss_score"] is None
