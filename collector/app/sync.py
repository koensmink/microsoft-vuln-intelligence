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


def utcnow():
    return datetime.now(timezone.utc)


def current_release_name() -> str:
    return utcnow().strftime("%Y-%b")


def fetch_release(release_name: str) -> dict:
    url = f"{MSRC_API_BASE_URL.rstrip('/')}/{release_name}"

    headers = {
        "Accept": "application/json",
        "User-Agent": "microsoft-vuln-intelligence/0.1",
    }

    with httpx.Client(timeout=60, follow_redirects=True, headers=headers) as client:
        response = client.get(url)

    content_type = response.headers.get("content-type", "")
    body_preview = response.text[:1000].replace("\n", " ").replace("\r", " ")

    if response.status_code != 200:
        raise RuntimeError(
            "MSRC request failed: "
            f"url={url}, "
            f"status={response.status_code}, "
            f"content_type={content_type}, "
            f"body_preview={body_preview}"
        )

    if "json" not in content_type.lower():
        raise RuntimeError(
            "MSRC response is not JSON: "
            f"url={url}, "
            f"status={response.status_code}, "
            f"content_type={content_type}, "
            f"body_preview={body_preview}"
        )

    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(
            "MSRC JSON parsing failed: "
            f"url={url}, "
            f"status={response.status_code}, "
            f"content_type={content_type}, "
            f"body_preview={body_preview}"
        ) from exc


from .cvrf_parser import parse_cvrf

def upsert(parsed: dict) -> None:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

    with engine.begin() as conn:
        run_id = conn.execute(
            text(
                """
                INSERT INTO sync_runs (release_name, started_at, status, records_processed)
                VALUES (:release_name, :started_at, 'running', 0)
                RETURNING id
                """
            ),
            {"release_name": parsed["release"]["release_name"], "started_at": utcnow()},
        ).scalar_one()

        try:
            release = parsed["release"]
            release_id = conn.execute(
                text(
                    """
                    INSERT INTO releases (release_name, release_date, revision_date, document_title, created_at, updated_at)
                    VALUES (:release_name, :release_date, :revision_date, :document_title, :created_at, :updated_at)
                    ON CONFLICT (release_name) DO UPDATE SET
                        release_date = EXCLUDED.release_date,
                        revision_date = EXCLUDED.revision_date,
                        document_title = EXCLUDED.document_title,
                        updated_at = EXCLUDED.updated_at
                    RETURNING id
                    """
                ),
                {**release, "created_at": utcnow(), "updated_at": utcnow()},
            ).scalar_one()

            product_db_ids = {}
            for product in parsed.get("products", {}).values():
                product_db_ids[product["product_id"]] = conn.execute(
                    text(
                        """
                        INSERT INTO products (product_id, name, cpe, family, created_at, updated_at)
                        VALUES (:product_id, :name, :cpe, :family, :created_at, :updated_at)
                        ON CONFLICT (product_id) DO UPDATE SET
                            name = EXCLUDED.name,
                            cpe = EXCLUDED.cpe,
                            family = EXCLUDED.family,
                            updated_at = EXCLUDED.updated_at
                        RETURNING id
                        """
                    ),
                    {**product, "created_at": utcnow(), "updated_at": utcnow()},
                ).scalar_one()

            count = 0
            for cve in parsed["cves"]:
                cve_db_id = conn.execute(
                    text(
                        """
                        INSERT INTO cves (cve_id, title, description, release_date, release_id, created_at, updated_at)
                        VALUES (:cve_id, :title, :description, :release_date, :release_id, :created_at, :updated_at)
                        ON CONFLICT (cve_id) DO UPDATE SET
                            title = EXCLUDED.title,
                            description = EXCLUDED.description,
                            release_date = EXCLUDED.release_date,
                            release_id = EXCLUDED.release_id,
                            updated_at = EXCLUDED.updated_at
                        RETURNING id
                        """
                    ),
                    {"cve_id": cve["cve_id"], "title": cve.get("title"), "description": cve.get("description"), "release_date": cve.get("release_date"), "release_id": release_id, "created_at": utcnow(), "updated_at": utcnow()},
                ).scalar_one()

                for pid, product in cve.get("products", {}).items():
                    if pid not in product_db_ids:
                        product_db_ids[pid] = conn.execute(
                            text("""
                            INSERT INTO products (product_id, name, cpe, family, created_at, updated_at)
                            VALUES (:product_id, :name, :cpe, :family, :created_at, :updated_at)
                            ON CONFLICT (product_id) DO UPDATE SET name = EXCLUDED.name, updated_at = EXCLUDED.updated_at
                            RETURNING id
                            """),
                            {"product_id": pid, "name": product.get("name") or pid, "cpe": product.get("cpe"), "family": product.get("family"), "created_at": utcnow(), "updated_at": utcnow()},
                        ).scalar_one()
                    pdata = cve.get("product_data", {}).get(pid, {})
                    conn.execute(
                        text("""
                        INSERT INTO cve_products (cve_id, product_id, status, severity, impact, cvss_base_score, cvss_temporal_score, cvss_vector, exploited, publicly_disclosed, created_at, updated_at)
                        VALUES (:cve_id, :product_id, :status, :severity, :impact, :cvss_base_score, :cvss_temporal_score, :cvss_vector, :exploited, :publicly_disclosed, :created_at, :updated_at)
                        ON CONFLICT (cve_id, product_id) DO UPDATE SET
                            status = EXCLUDED.status, severity = EXCLUDED.severity, impact = EXCLUDED.impact,
                            cvss_base_score = EXCLUDED.cvss_base_score, cvss_temporal_score = EXCLUDED.cvss_temporal_score,
                            cvss_vector = EXCLUDED.cvss_vector, exploited = EXCLUDED.exploited,
                            publicly_disclosed = EXCLUDED.publicly_disclosed, updated_at = EXCLUDED.updated_at
                        """),
                        {"cve_id": cve_db_id, "product_id": product_db_ids[pid], "status": pdata.get("status"), "severity": pdata.get("severity"), "impact": pdata.get("impact"), "cvss_base_score": pdata.get("cvss_base_score"), "cvss_temporal_score": pdata.get("cvss_temporal_score"), "cvss_vector": pdata.get("cvss_vector"), "exploited": cve.get("exploited", False), "publicly_disclosed": cve.get("publicly_disclosed", False), "created_at": utcnow(), "updated_at": utcnow()},
                    )

                for remediation in cve.get("remediations", []):
                    pid = remediation.get("product_id")
                    conn.execute(
                        text("""
                        INSERT INTO remediations (cve_id, product_id, remediation_type, subtype, description, url, created_at, updated_at)
                        VALUES (:cve_id, :product_id, :remediation_type, :subtype, :description, :url, :created_at, :updated_at)
                        ON CONFLICT (cve_id, product_id, remediation_type, description, url) DO NOTHING
                        """),
                        {**remediation, "cve_id": cve_db_id, "product_id": product_db_ids.get(pid), "created_at": utcnow(), "updated_at": utcnow()},
                    )
                count += 1

            conn.execute(text("UPDATE sync_runs SET finished_at = :finished_at, status = 'success', records_processed = :records_processed WHERE id = :id"), {"finished_at": utcnow(), "records_processed": count, "id": run_id})
        except Exception as exc:
            conn.execute(text("UPDATE sync_runs SET finished_at = :finished_at, status = 'failed', error_message = :error_message WHERE id = :id"), {"finished_at": utcnow(), "error_message": str(exc)[:4000], "id": run_id})
            raise

def main() -> None:
    release_name = sys.argv[1] if len(sys.argv) > 1 else current_release_name()

    document = fetch_release(release_name)
    parsed = parse_cvrf(document, release_name)
    upsert(parsed)

    print(f"synced {release_name}: {len(parsed['cves'])} CVEs")


if __name__ == "__main__":
    main()
