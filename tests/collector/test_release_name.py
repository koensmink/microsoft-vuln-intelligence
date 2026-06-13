from collector.app.sync import parse_cvrf

def test_collector_parser_is_minimal_and_idempotent_ready():
    parsed = parse_cvrf({'Vulnerability': [{'CVE': 'CVE-2026-0001'}]}, '2026-Jun')
    assert parsed['release']['release_name'] == '2026-Jun'
    assert parsed['cves'][0]['cve_id'] == 'CVE-2026-0001'
