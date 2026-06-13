import os
import sys
from datetime import datetime

import httpx
from sqlalchemy import create_engine, text

from app.cvrf_parser import parse_cvrf

MSRC_API_BASE_URL = os.getenv("MSRC_API_BASE_URL", "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+pysqlite:///./dev.db")


def current_release_name() -> str:
    return datetime.utcnow().strftime("%Y-%b")


def fetch_release(release_name: str) -> dict:
    with httpx.Client(timeout=60) as client:
        response = client.get(f"{MSRC_API_BASE_URL}/{release_name}")
        response.raise_for_status()
        return response.json()


def upsert(parsed: dict) -> int:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    with engine.begin() as conn:
        run_id = conn.execute(text("INSERT INTO sync_runs (started_at, status, records_processed) VALUES (:started, 'running', 0) RETURNING id"), {"started": datetime.utcnow()}).scalar_one()
        try:
            rel = parsed["release"]
            release_id = conn.execute(text("INSERT INTO releases (release_name, release_date, revision_date, document_title, created_at) VALUES (:release_name, :release_date, :revision_date, :document_title, :created_at) ON CONFLICT (release_name) DO UPDATE SET release_date=EXCLUDED.release_date, revision_date=EXCLUDED.revision_date, document_title=EXCLUDED.document_title RETURNING id"), {**rel, "created_at": datetime.utcnow()}).scalar_one()
            count = 0
            for cve in parsed["cves"]:
                cve_id = conn.execute(text("INSERT INTO cves (cve_id, title, description, severity, cvss_score, impact, exploited, publicly_disclosed, release_id, created_at, updated_at) VALUES (:cve_id, :title, :description, :severity, :cvss_score, :impact, :exploited, :publicly_disclosed, :release_id, :created_at, :updated_at) ON CONFLICT (cve_id) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, severity=EXCLUDED.severity, cvss_score=EXCLUDED.cvss_score, impact=EXCLUDED.impact, exploited=EXCLUDED.exploited, publicly_disclosed=EXCLUDED.publicly_disclosed, release_id=EXCLUDED.release_id, updated_at=EXCLUDED.updated_at RETURNING id"), {**{k: cve.get(k) for k in ["cve_id", "title", "description", "severity", "cvss_score", "impact", "exploited", "publicly_disclosed"]}, "release_id": release_id, "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()}).scalar_one()
                for affected in cve.get("affected_products", []):
                    product = affected["product"]
                    product_db_id = conn.execute(text("INSERT INTO products (name, family, vendor) VALUES (:name, :family, :vendor) ON CONFLICT (name) DO UPDATE SET family=EXCLUDED.family, vendor=EXCLUDED.vendor RETURNING id"), product).scalar_one()
                    conn.execute(text("INSERT INTO affected_products (cve_id, product_id, fixed_build, kb_article, download_url) VALUES (:cve_id, :product_id, :fixed_build, :kb_article, :download_url) ON CONFLICT (cve_id, product_id, fixed_build, kb_article) DO UPDATE SET download_url=EXCLUDED.download_url"), {"cve_id": cve_id, "product_id": product_db_id, "fixed_build": affected.get("fixed_build"), "kb_article": affected.get("kb_article"), "download_url": affected.get("download_url")})
                for remediation in cve.get("remediations", []):
                    conn.execute(text("INSERT INTO remediations (cve_id, remediation_type, description, url) VALUES (:cve_id, :remediation_type, :description, :url) ON CONFLICT (cve_id, remediation_type, url) DO UPDATE SET description=EXCLUDED.description"), {"cve_id": cve_id, **remediation})
                count += 1
            conn.execute(text("UPDATE sync_runs SET finished_at=:finished, status='success', records_processed=:count WHERE id=:id"), {"finished": datetime.utcnow(), "count": count, "id": run_id})
            return count
        except Exception as exc:
            conn.execute(text("UPDATE sync_runs SET finished_at=:finished, status='failed', error_message=:error WHERE id=:id"), {"finished": datetime.utcnow(), "error": str(exc), "id": run_id})
            raise


def main() -> None:
    release_name = sys.argv[1] if len(sys.argv) > 1 else current_release_name()
    count = upsert(parse_cvrf(fetch_release(release_name), release_name))
    print(f"synced {count} CVEs from {release_name}")
