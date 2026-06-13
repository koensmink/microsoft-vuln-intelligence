from backend.app.services.cvrf_parser import parse_cvrf

def test_parse_cvrf_extracts_cve():
    parsed = parse_cvrf({"DocumentTitle": {"Value": "June"}, "Vulnerability": [{"CVE": "CVE-2026-12345", "Title": {"Value": "Example"}, "Severity": "Critical", "PubliclyDisclosed": True}]}, "2026-Jun")
    assert parsed["release"]["release_name"] == "2026-Jun"
    assert parsed["cves"][0]["cve_id"] == "CVE-2026-12345"
    assert parsed["cves"][0]["publicly_disclosed"] is True
