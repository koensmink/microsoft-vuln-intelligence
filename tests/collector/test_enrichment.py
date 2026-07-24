from datetime import date, datetime

import httpx
import pytest

from collector.app import enrichment
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


class FakeResult:
    def __init__(self, row):
        self.row = row

    def one(self):
        return self.row


class FakeConnection:
    def __init__(self, bounds=(date(2026, 1, 1), date(2026, 1, 1))):
        self.bounds = bounds

    def execute(self, statement, params=None):
        if "MIN(release_date)" in str(statement):
            return FakeResult(self.bounds)
        return FakeResult(None)


class FakeClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, url, params=None):
        self.calls.append((url, params))
        return next(self.responses)


def response(status, body=None, headers=None):
    return httpx.Response(status, json=body or {}, headers=headers, request=httpx.Request("GET", "https://nvd.test"))


def vulnerability(cve_id):
    return {"cve": {"id": cve_id, "metrics": {}}}


def test_client_sends_api_key_without_logging(monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", "private-key")
    with enrichment._client() as client:
        assert client.headers["apiKey"] == "private-key"
    assert "private-key" not in capsys.readouterr().err


def test_nvd_batches_pages_windows_and_filters_local_cves(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    conn = FakeConnection((date(2026, 1, 1), date(2026, 5, 2)))
    client = FakeClient([
        response(200, {"totalResults": 3, "vulnerabilities": [vulnerability("CVE-2026-1"), vulnerability("CVE-other")]}),
        response(200, {"totalResults": 3, "vulnerabilities": [vulnerability("CVE-2026-2")]}),
        response(200, {"totalResults": 0, "vulnerabilities": []}),
    ])
    stored = []
    sleeps = []
    monkeypatch.setattr(enrichment, "_client", lambda: client)
    monkeypatch.setattr(enrichment, "upsert_enrichment", lambda conn, cve_id, source, payload: stored.append((cve_id, source)))
    monkeypatch.setattr(enrichment.time, "sleep", sleeps.append)

    assert enrichment.enrich_nvd(conn, ["CVE-2026-1", "CVE-2026-2"]) == 2
    assert stored == [("CVE-2026-1", "nvd"), ("CVE-2026-2", "nvd")]
    assert [call[1]["startIndex"] for call in client.calls] == [0, 2, 0]
    assert all(call[1]["resultsPerPage"] <= 2000 for call in client.calls)
    starts = [datetime.fromisoformat(call[1]["pubStartDate"]) for call in client.calls if call[1]["startIndex"] == 0]
    ends = [datetime.fromisoformat(call[1]["pubEndDate"]) for call in client.calls if call[1]["startIndex"] == 0]
    assert all(end - start <= enrichment.timedelta(days=120) for start, end in zip(starts, ends))
    assert sleeps == [enrichment.NVD_REQUEST_DELAY_WITHOUT_API_KEY, enrichment.NVD_REQUEST_DELAY_WITHOUT_API_KEY]


def test_nvd_request_delay_uses_api_key_rate(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "mock-api-key")
    assert enrichment._nvd_request_delay() == enrichment.NVD_REQUEST_DELAY_WITH_API_KEY


@pytest.mark.parametrize("status,headers,body,minimum", [
    (429, {"Retry-After": "12"}, {}, 12),
    (429, {}, {}, 1),
    (429, {}, {"error_code": 1015}, enrichment.NVD_CLOUDFLARE_BACKOFF_SECONDS),
    (500, {}, {}, 1),
])
def test_nvd_retries_transient_errors(monkeypatch, capsys, status, headers, body, minimum):
    client = FakeClient([response(status, body, headers), response(200, {"vulnerabilities": []})])
    sleeps = []
    monkeypatch.setattr(enrichment.time, "sleep", sleeps.append)
    monkeypatch.setattr(enrichment.random, "uniform", lambda *_: 0)

    assert enrichment._nvd_get(client, {}) == {"vulnerabilities": []}
    assert sleeps[0] >= minimum
    assert "attempt=1" in capsys.readouterr().err


def test_nvd_stops_after_maximum_retries(monkeypatch):
    client = FakeClient([response(429) for _ in range(enrichment.NVD_MAX_ATTEMPTS)])
    monkeypatch.setattr(enrichment.time, "sleep", lambda _: None)
    with pytest.raises(RuntimeError, match="after 5 attempts"):
        enrichment._nvd_get(client, {})


def test_nvd_partial_records_and_repeated_runs_use_existing_upsert(monkeypatch):
    conn = FakeConnection((date(2026, 1, 1), date(2026, 5, 2)))
    stored = []
    monkeypatch.setattr(enrichment, "upsert_enrichment", lambda conn, cve_id, source, payload: stored.append((cve_id, source)))
    monkeypatch.setattr(enrichment.time, "sleep", lambda _: None)
    first = FakeClient([response(200, {"totalResults": 1, "vulnerabilities": [vulnerability("CVE-2026-1")]}), *[response(500) for _ in range(enrichment.NVD_MAX_ATTEMPTS)]])
    monkeypatch.setattr(enrichment, "_client", lambda: first)
    with pytest.raises(RuntimeError):
        enrichment.enrich_nvd(conn, ["CVE-2026-1"])
    assert stored == [("CVE-2026-1", "nvd")]

    second = FakeClient([response(200, {"totalResults": 1, "vulnerabilities": [vulnerability("CVE-2026-1")]}), response(200, {"totalResults": 0, "vulnerabilities": []})])
    monkeypatch.setattr(enrichment, "_client", lambda: second)
    enrichment.enrich_nvd(conn, ["CVE-2026-1"])
    assert stored == [("CVE-2026-1", "nvd"), ("CVE-2026-1", "nvd")]


@pytest.mark.parametrize("source", ["epss", "kev"])
def test_nvd_failure_does_not_block_other_sources(monkeypatch, source):
    calls = []
    monkeypatch.setattr(enrichment, "create_engine", lambda *args, **kwargs: type("Engine", (), {"begin": lambda self: type("Context", (), {"__enter__": lambda self: FakeConnection(), "__exit__": lambda self, *args: False})()})())
    monkeypatch.setattr(enrichment, "existing_cve_ids", lambda *args: ["CVE-2026-1"])
    monkeypatch.setattr(enrichment, "enrich_nvd", lambda *args: (_ for _ in ()).throw(RuntimeError("rate limited")))
    monkeypatch.setattr(enrichment, "enrich_epss", lambda *args: calls.append("epss") or 1)
    monkeypatch.setattr(enrichment, "enrich_kev", lambda *args: calls.append("kev") or 1)
    monkeypatch.setattr(enrichment.sys, "argv", ["enrichment.py"])

    enrichment.main()
    assert source in calls
