import os
import sys
from pathlib import Path
from datetime import datetime, timezone

import httpx
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqlalchemy import create_engine, text


MSRC_API_BASE_URL = os.getenv(
    "MSRC_API_BASE_URL",
    "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf",
)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+pysqlite:///./dev.db",
)

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def utcnow():
    return datetime.now(timezone.utc)


def current_release_name() -> str:
    return utcnow().strftime("%Y-%b")


def previous_release_name() -> str:
    now = utcnow()
    year = now.year
    month = now.month - 1
    if month == 0:
        month = 12
        year -= 1
    return f"{year}-{MONTHS[month - 1]}"


def updates_url() -> str:
    base = MSRC_API_BASE_URL.rstrip("/")
    if base.endswith("/cvrf"):
        return f"{base[:-5]}/updates"
    return f"{base}/updates"


def _client() -> httpx.Client:
    return httpx.Client(
        timeout=60,
        follow_redirects=True,
        headers={"Accept": "application/json", "User-Agent": "microsoft-vuln-intelligence/0.1"},
    )


def _json_response(response: httpx.Response, url: str) -> dict:
    content_type = response.headers.get("content-type", "")
    body_preview = response.text[:1000].replace("\n", " ").replace("\r", " ")
    if response.status_code != 200:
        raise RuntimeError(
            "MSRC request failed: "
            f"url={url}, status={response.status_code}, content_type={content_type}, body_preview={body_preview}"
        )
    if "json" not in content_type.lower():
        raise RuntimeError(
            "MSRC response is not JSON: "
            f"url={url}, status={response.status_code}, content_type={content_type}, body_preview={body_preview}"
        )
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(
            "MSRC JSON parsing failed: "
            f"url={url}, status={response.status_code}, content_type={content_type}, body_preview={body_preview}"
        ) from exc


def fetch_updates() -> list[dict]:
    url = updates_url()
    with _client() as client:
        payload = _json_response(client.get(url), url)
    return payload.get("value", [])


def fetch_release(release_name: str) -> dict:
    url = f"{MSRC_API_BASE_URL.rstrip('/')}/{release_name}"
    with _client() as client:
        return _json_response(client.get(url), url)


def normalize_release(update: dict) -> dict:
    release_name = update.get("ID") or update.get("Alias")
    return {
        "release_name": release_name,
        "alias": update.get("Alias"),
        "document_title": update.get("DocumentTitle"),
        "severity": update.get("Severity"),
        "release_date": update.get("InitialReleaseDate"),
        "revision_date": update.get("CurrentReleaseDate"),
        "cvrf_url": update.get("CvrfUrl"),
    }


from .cvrf_parser import parse_cvrf


def _row_mapping(row):
    return dict(row._mapping) if row else None


def _changed(existing: dict | None, values: dict, keys: list[str]) -> bool:
    if existing is None:
        return True
    return any(str(existing.get(key)) != str(values.get(key)) for key in keys)


def upsert_release_metadata(conn, update: dict, synced_at=None) -> tuple[int, bool, bool]:
    release = normalize_release(update)
    if not release["release_name"]:
        raise RuntimeError(f"MSRC update entry is missing release ID: {update}")
    existing = _row_mapping(conn.execute(text("SELECT * FROM releases WHERE release_name = :release_name"), {"release_name": release["release_name"]}).first())
    now = utcnow()
    params = {**release, "last_synced_at": synced_at or (existing or {}).get("last_synced_at"), "created_at": now, "updated_at": now}
    release_id = conn.execute(
        text(
            """
            INSERT INTO releases (release_name, alias, release_date, revision_date, document_title, severity, cvrf_url, last_synced_at, created_at, updated_at)
            VALUES (:release_name, :alias, :release_date, :revision_date, :document_title, :severity, :cvrf_url, :last_synced_at, :created_at, :updated_at)
            ON CONFLICT (release_name) DO UPDATE SET
                alias = EXCLUDED.alias,
                release_date = EXCLUDED.release_date,
                revision_date = EXCLUDED.revision_date,
                document_title = EXCLUDED.document_title,
                severity = EXCLUDED.severity,
                cvrf_url = EXCLUDED.cvrf_url,
                last_synced_at = COALESCE(EXCLUDED.last_synced_at, releases.last_synced_at),
                updated_at = EXCLUDED.updated_at
            RETURNING id
            """
        ),
        params,
    ).scalar_one()
    changed = _changed(existing, release, ["alias", "release_date", "revision_date", "document_title", "severity", "cvrf_url"])
    return release_id, existing is None, existing is not None and changed


def sync_parsed_release(conn, parsed: dict, update: dict | None = None) -> dict[str, int]:
    counts = {"releases_added": 0, "releases_updated": 0, "cves_added": 0, "cves_updated": 0, "products_added": 0, "products_updated": 0}
    synced_at = utcnow()
    release_update = update or {
        "ID": parsed["release"]["release_name"],
        "DocumentTitle": parsed["release"].get("document_title"),
        "InitialReleaseDate": parsed["release"].get("release_date"),
        "CurrentReleaseDate": parsed["release"].get("revision_date"),
    }
    release_id, added, updated = upsert_release_metadata(conn, release_update, synced_at=synced_at)
    counts["releases_added"] += int(added)
    counts["releases_updated"] += int(updated or (not added))

    product_db_ids = {}
    for product in parsed.get("products", {}).values():
        existing = _row_mapping(conn.execute(text("SELECT * FROM products WHERE product_id = :product_id"), {"product_id": product["product_id"]}).first())
        product_db_ids[product["product_id"]] = conn.execute(
            text(
                """
                INSERT INTO products (product_id, name, cpe, family, created_at, updated_at)
                VALUES (:product_id, :name, :cpe, :family, :created_at, :updated_at)
                ON CONFLICT (product_id) DO UPDATE SET name = EXCLUDED.name, cpe = EXCLUDED.cpe, family = EXCLUDED.family, updated_at = EXCLUDED.updated_at
                RETURNING id
                """
            ),
            {**product, "created_at": utcnow(), "updated_at": utcnow()},
        ).scalar_one()
        counts["products_added"] += int(existing is None)
        counts["products_updated"] += int(existing is not None and _changed(existing, product, ["name", "cpe", "family"]))

    for cve in parsed["cves"]:
        existing_cve = _row_mapping(conn.execute(text("SELECT * FROM cves WHERE cve_id = :cve_id"), {"cve_id": cve["cve_id"]}).first())
        cve_values = {"cve_id": cve["cve_id"], "title": cve.get("title"), "description": cve.get("description"), "release_date": cve.get("release_date"), "release_id": release_id}
        cve_db_id = conn.execute(
            text(
                """
                INSERT INTO cves (cve_id, title, description, release_date, release_id, created_at, updated_at)
                VALUES (:cve_id, :title, :description, :release_date, :release_id, :created_at, :updated_at)
                ON CONFLICT (cve_id) DO UPDATE SET title = EXCLUDED.title, description = EXCLUDED.description, release_date = EXCLUDED.release_date, release_id = EXCLUDED.release_id, updated_at = EXCLUDED.updated_at
                RETURNING id
                """
            ),
            {**cve_values, "created_at": utcnow(), "updated_at": utcnow()},
        ).scalar_one()
        cve_changed = _changed(existing_cve, cve_values, ["title", "description", "release_date", "release_id"])

        for pid, product in cve.get("products", {}).items():
            if pid not in product_db_ids:
                product_db_ids[pid] = conn.execute(text("INSERT INTO products (product_id, name, cpe, family, created_at, updated_at) VALUES (:product_id, :name, :cpe, :family, :created_at, :updated_at) ON CONFLICT (product_id) DO UPDATE SET name = EXCLUDED.name, updated_at = EXCLUDED.updated_at RETURNING id"), {"product_id": pid, "name": product.get("name") or pid, "cpe": product.get("cpe"), "family": product.get("family"), "created_at": utcnow(), "updated_at": utcnow()}).scalar_one()
            pdata = cve.get("product_data", {}).get(pid, {})
            existing_link = _row_mapping(conn.execute(text("SELECT * FROM cve_products WHERE cve_id = :cve_id AND product_id = :product_id"), {"cve_id": cve_db_id, "product_id": product_db_ids[pid]}).first())
            link_values = {"cve_id": cve_db_id, "product_id": product_db_ids[pid], "status": pdata.get("status"), "severity": pdata.get("severity"), "impact": pdata.get("impact"), "cvss_base_score": pdata.get("cvss_base_score"), "cvss_temporal_score": pdata.get("cvss_temporal_score"), "cvss_vector": pdata.get("cvss_vector"), "exploited": cve.get("exploited", False), "publicly_disclosed": cve.get("publicly_disclosed", False)}
            conn.execute(text("""
                INSERT INTO cve_products (cve_id, product_id, status, severity, impact, cvss_base_score, cvss_temporal_score, cvss_vector, exploited, publicly_disclosed, created_at, updated_at)
                VALUES (:cve_id, :product_id, :status, :severity, :impact, :cvss_base_score, :cvss_temporal_score, :cvss_vector, :exploited, :publicly_disclosed, :created_at, :updated_at)
                ON CONFLICT (cve_id, product_id) DO UPDATE SET status = EXCLUDED.status, severity = EXCLUDED.severity, impact = EXCLUDED.impact, cvss_base_score = EXCLUDED.cvss_base_score, cvss_temporal_score = EXCLUDED.cvss_temporal_score, cvss_vector = EXCLUDED.cvss_vector, exploited = EXCLUDED.exploited, publicly_disclosed = EXCLUDED.publicly_disclosed, updated_at = EXCLUDED.updated_at
            """), {**link_values, "created_at": utcnow(), "updated_at": utcnow()})
            cve_changed = cve_changed or _changed(existing_link, link_values, ["status", "severity", "impact", "cvss_base_score", "cvss_temporal_score", "cvss_vector", "exploited", "publicly_disclosed"])

        for remediation in cve.get("remediations", []):
            pid = remediation.get("product_id")
            conn.execute(text("""
                INSERT INTO remediations (cve_id, product_id, remediation_type, subtype, description, url, created_at, updated_at)
                VALUES (:cve_id, :product_id, :remediation_type, :subtype, :description, :url, :created_at, :updated_at)
                ON CONFLICT (cve_id, product_id, remediation_type, description, url) DO UPDATE SET subtype = EXCLUDED.subtype, updated_at = EXCLUDED.updated_at
            """), {**remediation, "cve_id": cve_db_id, "product_id": product_db_ids.get(pid), "created_at": utcnow(), "updated_at": utcnow()})
        counts["cves_added"] += int(existing_cve is None)
        counts["cves_updated"] += int(existing_cve is not None and cve_changed)
    return counts


def choose_releases_to_sync(conn, updates: list[dict], requested_release: str | None = None) -> list[dict]:
    releases = [normalize_release(update) | {"raw": update} for update in updates if normalize_release(update).get("release_name")]
    by_name = {release["release_name"]: release for release in releases}
    if requested_release:
        return [by_name.get(requested_release, {"release_name": requested_release, "raw": {"ID": requested_release}})["raw"]]
    selected = {name for name in (current_release_name(), previous_release_name()) if name in by_name}
    for release in releases:
        existing = _row_mapping(conn.execute(text("SELECT revision_date, last_synced_at FROM releases WHERE release_name = :release_name"), {"release_name": release["release_name"]}).first())
        if existing and existing.get("last_synced_at") and str(existing.get("revision_date")) != str(release.get("revision_date")):
            selected.add(release["release_name"])
    return [by_name[name]["raw"] for name in sorted(selected)]


def upsert(parsed: dict) -> None:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    with engine.begin() as conn:
        sync_parsed_release(conn, parsed)


def main() -> None:
    requested_release = sys.argv[1] if len(sys.argv) > 1 else None
    updates = fetch_updates()
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    totals = {"releases_added": 0, "releases_updated": 0, "cves_added": 0, "cves_updated": 0, "products_added": 0, "products_updated": 0}

    with engine.begin() as conn:
        targets = choose_releases_to_sync(conn, updates, requested_release)
        for update in updates:
            _, added, updated = upsert_release_metadata(conn, update)
            totals["releases_added"] += int(added)
            totals["releases_updated"] += int(updated)

    print(f"MSRC /updates returned {len(updates)} releases; syncing {len(targets)} releases")

    for update in targets:
        release_name = update.get("ID") or update.get("Alias")
        with engine.begin() as conn:
            run_id = conn.execute(text("INSERT INTO sync_runs (release_name, started_at, status, records_processed) VALUES (:release_name, :started_at, 'running', 0) RETURNING id"), {"release_name": release_name, "started_at": utcnow()}).scalar_one()
        try:
            document = fetch_release(release_name)
            parsed = parse_cvrf(document, release_name)
            with engine.begin() as conn:
                counts = sync_parsed_release(conn, parsed, update)
                for key, value in counts.items():
                    totals[key] += value
                conn.execute(text("UPDATE sync_runs SET finished_at = :finished_at, status = 'success', records_processed = :records_processed WHERE id = :id"), {"finished_at": utcnow(), "records_processed": len(parsed["cves"]), "id": run_id})
            print(f"synced {release_name}: {len(parsed['cves'])} CVEs")
        except Exception as exc:
            with engine.begin() as conn:
                conn.execute(text("UPDATE sync_runs SET finished_at = :finished_at, status = 'failed', error_message = :error_message WHERE id = :id"), {"finished_at": utcnow(), "error_message": str(exc)[:4000], "id": run_id})
            raise

    print(
        "sync summary: "
        f"releases added={totals['releases_added']} updated={totals['releases_updated']}; "
        f"CVEs added={totals['cves_added']} updated={totals['cves_updated']}; "
        f"products added={totals['products_added']} updated={totals['products_updated']}"
    )


if __name__ == "__main__":
    main()
