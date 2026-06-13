from collector.app.cvrf_parser import parse_cvrf


def test_collector_parser_extracts_affected_product():
    parsed = parse_cvrf({
        'ProductTree': {'FullProductName': [{'ProductID': 'p1', 'Value': 'Microsoft Edge'}]},
        'Vulnerability': [{'CVE': 'CVE-2026-0001', 'ProductStatuses': [{'ProductID': ['p1']}]}],
    }, '2026-Jun')
    assert parsed['release']['release_name'] == '2026-Jun'
    assert parsed['cves'][0]['cve_id'] == 'CVE-2026-0001'
    assert parsed['cves'][0]['affected_products'][0]['product']['name'] == 'Microsoft Edge'
