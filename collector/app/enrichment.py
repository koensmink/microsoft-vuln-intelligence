import json
import os
import random
import sys
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqlalchemy import bindparam, create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+pysqlite:///./dev.db")
NVD_API_BASE_URL = os.getenv("NVD_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
EPSS_API_BASE_URL = os.getenv("EPSS_API_BASE_URL", "https://api.first.org/data/v1/epss")
KEV_CATALOG_URL = os.getenv("KEV_CATALOG_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
NVD_RESULTS_PER_PAGE = 2000
NVD_WINDOW_DAYS = 120
NVD_MAX_ATTEMPTS = 5
NVD_REQUEST_DELAY_WITH_API_KEY = 1.0
NVD_REQUEST_DELAY_WITHOUT_API_KEY = 7.0
NVD_CLOUDFLARE_BACKOFF_SECONDS = 60.0


def utcnow():
    return datetime.now(timezone.utc)


def _client() -> httpx.Client:
    headers = {"Accept": "application/json", "User-Agent": "microsoft-vuln-intelligence/0.1"}
    if api_key := os.getenv("NVD_API_KEY"):
        headers["apiKey"] = api_key
    return httpx.Client(timeout=60, follow_redirects=True, headers=headers)


def _json_response(response: httpx.Response, source: str) -> dict[str, Any]:
    if response.status_code != 200:
        raise RuntimeError(f"{source} request failed: status={response.status_code}, body={response.text[:500]}")
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(f"{source} response was not valid JSON") from exc


def existing_cve_ids(conn, requested: list[str] | None = None) -> list[str]:
    if requested:
        stmt = text("SELECT cve_id FROM cves WHERE cve_id IN :cve_ids").bindparams(bindparam("cve_ids", expanding=True))
        rows = conn.execute(stmt, {"cve_ids": requested}).all()
    else:
        rows = conn.execute(text("SELECT cve_id FROM cves ORDER BY cve_id")).all()
    return [row[0] for row in rows]


def upsert_enrichment(conn, cve_id: str, source: str, payload: dict[str, Any]) -> None:
    now = utcnow()
    conn.execute(
        text(
            """
            INSERT INTO cve_enrichment (
                cve_id, source, cvss_score, cvss_vector, severity, epss_score, epss_percentile,
                kev_known_exploited, kev_due_date, kev_vendor_project, kev_product,
                kev_required_action, kev_notes, raw_json, fetched_at, created_at, updated_at
            ) VALUES (
                (SELECT id FROM cves WHERE cve_id = :cve_id), :source, :cvss_score, :cvss_vector, :severity,
                :epss_score, :epss_percentile, :kev_known_exploited, :kev_due_date, :kev_vendor_project,
                :kev_product, :kev_required_action, :kev_notes, :raw_json, :fetched_at, :created_at, :updated_at
            )
            ON CONFLICT (cve_id, source) DO UPDATE SET
                cvss_score = EXCLUDED.cvss_score,
                cvss_vector = EXCLUDED.cvss_vector,
                severity = EXCLUDED.severity,
                epss_score = EXCLUDED.epss_score,
                epss_percentile = EXCLUDED.epss_percentile,
                kev_known_exploited = EXCLUDED.kev_known_exploited,
                kev_due_date = EXCLUDED.kev_due_date,
                kev_vendor_project = EXCLUDED.kev_vendor_project,
                kev_product = EXCLUDED.kev_product,
                kev_required_action = EXCLUDED.kev_required_action,
                kev_notes = EXCLUDED.kev_notes,
                raw_json = EXCLUDED.raw_json,
                fetched_at = EXCLUDED.fetched_at,
                updated_at = EXCLUDED.updated_at
            """
        ),
        {"cve_id": cve_id, "source": source, "fetched_at": now, "created_at": now, "updated_at": now, **payload},
    )


def parse_nvd(vuln: dict[str, Any]) -> dict[str, Any]:
    metrics = vuln.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key, []):
            data = metric.get("cvssData", {})
            if data:
                return {
                    "cvss_score": data.get("baseScore"),
                    "cvss_vector": data.get("vectorString"),
                    "severity": metric.get("baseSeverity") or data.get("baseSeverity"),
                    "epss_score": None,
                    "epss_percentile": None,
                    "kev_known_exploited": None,
                    "kev_due_date": None,
                    "kev_vendor_project": None,
                    "kev_product": None,
                    "kev_required_action": None,
                    "kev_notes": None,
                    "raw_json": json.dumps(vuln, sort_keys=True),
                }
    return {"cvss_score": None, "cvss_vector": None, "severity": None, "epss_score": None, "epss_percentile": None, "kev_known_exploited": None, "kev_due_date": None, "kev_vendor_project": None, "kev_product": None, "kev_required_action": None, "kev_notes": None, "raw_json": json.dumps(vuln, sort_keys=True)}


def _nvd_request_delay() -> float:
    return NVD_REQUEST_DELAY_WITH_API_KEY if os.getenv("NVD_API_KEY") else NVD_REQUEST_DELAY_WITHOUT_API_KEY


def _nvd_retry_delay(response: httpx.Response, attempt: int) -> float:
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return max(float(retry_after), NVD_CLOUDFLARE_BACKOFF_SECONDS if "1015" in response.text else 0.0)
        except ValueError:
            pass
    delay = (2 ** (attempt - 1)) + random.uniform(0, 1)
    return max(delay, NVD_CLOUDFLARE_BACKOFF_SECONDS if "1015" in response.text else 0.0)


def _nvd_get(client: httpx.Client, params: dict[str, Any]) -> dict[str, Any]:
    for attempt in range(1, NVD_MAX_ATTEMPTS + 1):
        response = client.get(NVD_API_BASE_URL, params=params)
        if response.status_code == 200:
            return _json_response(response, "NVD")
        retryable = response.status_code in (403, 429) or 500 <= response.status_code < 600
        if not retryable:
            return _json_response(response, "NVD")
        if attempt == NVD_MAX_ATTEMPTS:
            raise RuntimeError(f"NVD request failed after {attempt} attempts: status={response.status_code}")
        delay = _nvd_retry_delay(response, attempt)
        print(f"NVD request retry attempt={attempt} status={response.status_code} wait={delay:.1f}s", file=sys.stderr)
        time.sleep(delay)
    raise RuntimeError("NVD request retries exhausted")


def _nvd_date_bounds(conn) -> tuple[datetime, datetime]:
    row = conn.execute(text("SELECT MIN(release_date), MAX(release_date) FROM cves WHERE release_date IS NOT NULL")).one()
    # There is no run-level NVD cursor in the existing schema, so release dates are
    # the reliable bounded source for a full NVD refresh.
    start = date.fromisoformat(row[0]) if isinstance(row[0], str) else row[0] or date(1999, 1, 1)
    end = date.fromisoformat(row[1]) if isinstance(row[1], str) else row[1] or utcnow().date()
    return (
        datetime.combine(start, datetime.min.time(), tzinfo=timezone.utc),
        datetime.combine(end, datetime.max.time(), tzinfo=timezone.utc),
    )


def _nvd_windows(conn):
    start, end = _nvd_date_bounds(conn)
    while start <= end:
        window_end = min(start + timedelta(days=NVD_WINDOW_DAYS) - timedelta(microseconds=1), end)
        yield start, window_end
        start = window_end + timedelta(microseconds=1)


def enrich_nvd(conn, cve_ids: list[str]) -> int:
    wanted = set(cve_ids)
    count = 0
    request_made = False
    with _client() as client:
        for window_start, window_end in _nvd_windows(conn):
            start_index = 0
            while True:
                if request_made:
                    time.sleep(_nvd_request_delay())
                payload = _nvd_get(client, {
                    "pubStartDate": window_start.isoformat(timespec="milliseconds"),
                    "pubEndDate": window_end.isoformat(timespec="milliseconds"),
                    "resultsPerPage": NVD_RESULTS_PER_PAGE,
                    "startIndex": start_index,
                })
                request_made = True
                vulnerabilities = payload.get("vulnerabilities") or []
                for vuln in vulnerabilities:
                    cve_id = vuln.get("cve", {}).get("id")
                    if cve_id in wanted:
                        upsert_enrichment(conn, cve_id, "nvd", parse_nvd(vuln))
                        count += 1
                start_index += len(vulnerabilities)
                if start_index >= payload.get("totalResults", 0) or not vulnerabilities:
                    break
    return count


def enrich_epss(conn, cve_ids: list[str]) -> int:
    count = 0
    with _client() as client:
        for i in range(0, len(cve_ids), 100):
            batch = cve_ids[i : i + 100]
            payload = _json_response(client.get(EPSS_API_BASE_URL, params={"cve": ",".join(batch)}), "FIRST EPSS")
            for item in payload.get("data", []):
                upsert_enrichment(conn, item["cve"], "epss", {"cvss_score": None, "cvss_vector": None, "severity": None, "epss_score": float(item["epss"]), "epss_percentile": float(item["percentile"]), "kev_known_exploited": None, "kev_due_date": None, "kev_vendor_project": None, "kev_product": None, "kev_required_action": None, "kev_notes": None, "raw_json": json.dumps(item, sort_keys=True)})
                count += 1
    return count


def enrich_kev(conn, cve_ids: list[str]) -> int:
    wanted = set(cve_ids)
    count = 0
    with _client() as client:
        payload = _json_response(client.get(KEV_CATALOG_URL), "CISA KEV")
    for item in payload.get("vulnerabilities", []):
        cve_id = item.get("cveID")
        if cve_id in wanted:
            upsert_enrichment(conn, cve_id, "kev", {"cvss_score": None, "cvss_vector": None, "severity": None, "epss_score": None, "epss_percentile": None, "kev_known_exploited": True, "kev_due_date": item.get("dueDate"), "kev_vendor_project": item.get("vendorProject"), "kev_product": item.get("product"), "kev_required_action": item.get("requiredAction"), "kev_notes": item.get("notes"), "raw_json": json.dumps(item, sort_keys=True)})
            count += 1
    return count


def main() -> None:
    requested = sys.argv[1:] or None
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    with engine.begin() as conn:
        cve_ids = existing_cve_ids(conn, requested)
        totals = {"nvd": 0, "kev": 0, "epss": 0}
        for source, func in (("nvd", enrich_nvd), ("kev", enrich_kev), ("epss", enrich_epss)):
            try:
                totals[source] = func(conn, cve_ids)
            except Exception as exc:
                print(f"{source} enrichment failed without blocking other sources: {exc}", file=sys.stderr)
    print(f"enrichment summary: CVEs={len(cve_ids)} nvd={totals['nvd']} kev={totals['kev']} epss={totals['epss']}")


if __name__ == "__main__":
    main()
