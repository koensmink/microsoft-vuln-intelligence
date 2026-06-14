import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqlalchemy import bindparam, create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+pysqlite:///./dev.db")
NVD_API_BASE_URL = os.getenv("NVD_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
EPSS_API_BASE_URL = os.getenv("EPSS_API_BASE_URL", "https://api.first.org/data/v1/epss")
KEV_CATALOG_URL = os.getenv("KEV_CATALOG_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")


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


def enrich_nvd(conn, cve_ids: list[str]) -> int:
    count = 0
    with _client() as client:
        for cve_id in cve_ids:
            payload = _json_response(client.get(NVD_API_BASE_URL, params={"cveId": cve_id}), "NVD")
            vulnerabilities = payload.get("vulnerabilities") or []
            if vulnerabilities:
                upsert_enrichment(conn, cve_id, "nvd", parse_nvd(vulnerabilities[0]))
                count += 1
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
