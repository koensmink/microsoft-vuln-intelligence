from app.services.cvrf_parser import parse_cvrf


def test_parse_cvrf_extracts_cve_products_and_remediations():
    parsed = parse_cvrf({
        "DocumentTitle": {"Value": "June"},
        "ProductTree": {"FullProductName": [{"ProductID": "1000", "Value": "Windows Server", "ProductFamilyName": "Windows"}]},
        "Vulnerability": [{
            "CVE": "CVE-2026-12345",
            "Title": {"Value": "Example"},
            "Severity": "Critical",
            "PubliclyDisclosed": True,
            "ProductStatuses": [{"ProductID": ["1000"]}],
            "Remediations": [{"Type": "Vendor Fix", "Description": "KB123", "URL": "https://example.test/kb123", "ProductID": ["1000"]}],
        }],
    }, "2026-Jun")
    assert parsed["release"]["release_name"] == "2026-Jun"
    assert parsed["cves"][0]["cve_id"] == "CVE-2026-12345"
    assert parsed["cves"][0]["publicly_disclosed"] is True
    assert parsed["cves"][0]["affected_products"][0]["product"]["name"] == "Windows Server"
    assert parsed["cves"][0]["remediations"][0]["description"] == "KB123"
