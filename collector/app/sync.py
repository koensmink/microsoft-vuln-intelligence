import os, sys
from datetime import datetime
import httpx
from sqlalchemy import create_engine, text
MSRC_API_BASE_URL = os.getenv("MSRC_API_BASE_URL", "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+pysqlite:///./dev.db")
def current_release_name():
    return datetime.utcnow().strftime("%Y-%b")
def parse_cvrf(document, release_name):
    vulns = document.get("Vulnerability", []) or []
    return {"release": {"release_name": release_name, "document_title": str(document.get("DocumentTitle", ""))[:255]}, "cves": [{"cve_id": v.get("CVE"), "title": str(v.get("Title", ""))[:255], "severity": v.get("Severity"), "exploited": bool(v.get("Exploited")), "publicly_disclosed": bool(v.get("PubliclyDisclosed"))} for v in vulns if v.get("CVE")]}
def fetch_release(release_name):
    with httpx.Client(timeout=60) as client:
        response = client.get(f"{MSRC_API_BASE_URL}/{release_name}")
        response.raise_for_status()
        return response.json()
def upsert(parsed):
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    with engine.begin() as conn:
        run_id = conn.execute(text("INSERT INTO sync_runs (started_at, status, records_processed) VALUES (:started, 'running', 0) RETURNING id"), {"started": datetime.utcnow()}).scalar_one()
        try:
            rel = parsed["release"]
            release_id = conn.execute(text("INSERT INTO releases (release_name, document_title, created_at) VALUES (:name, :title, :created) ON CONFLICT (release_name) DO UPDATE SET document_title = EXCLUDED.document_title RETURNING id"), {"name": rel["release_name"], "title": rel.get("document_title"), "created": datetime.utcnow()}).scalar_one()
            count = 0
            for cve in parsed["cves"]:
                conn.execute(text("INSERT INTO cves (cve_id, title, severity, exploited, publicly_disclosed, release_id, created_at, updated_at) VALUES (:cve_id, :title, :severity, :exploited, :publicly_disclosed, :release_id, :created, :updated) ON CONFLICT (cve_id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity, exploited=EXCLUDED.exploited, publicly_disclosed=EXCLUDED.publicly_disclosed, release_id=EXCLUDED.release_id, updated_at=EXCLUDED.updated_at"), {**cve, "release_id": release_id, "created": datetime.utcnow(), "updated": datetime.utcnow()})
                count += 1
            conn.execute(text("UPDATE sync_runs SET finished_at=:finished, status='success', records_processed=:count WHERE id=:id"), {"finished": datetime.utcnow(), "count": count, "id": run_id})
        except Exception as exc:
            conn.execute(text("UPDATE sync_runs SET finished_at=:finished, status='failed', error_message=:error WHERE id=:id"), {"finished": datetime.utcnow(), "error": str(exc), "id": run_id})
            raise
def main():
    release_name = sys.argv[1] if len(sys.argv) > 1 else current_release_name()
    upsert(parse_cvrf(fetch_release(release_name), release_name))
    print(f"synced {release_name}")
