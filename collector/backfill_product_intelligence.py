import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sqlalchemy import create_engine, text
from collector.app.product_intelligence import RAW_PRODUCT_NAME_COLUMN, upsert_product_mapping

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+pysqlite:///./dev.db")

def utcnow():
    return datetime.now(timezone.utc)

def backfill() -> dict[str, int]:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    counts = {"products_seen": 0, "links_updated": 0, "mappings_upserted": 0}
    with engine.begin() as conn:
        rows = conn.execute(text(f"""
            SELECT cp.id AS link_id, p.{RAW_PRODUCT_NAME_COLUMN} AS raw_name
            FROM cve_products cp JOIN products p ON p.id = cp.product_id
        """)).mappings().all()
        for row in rows:
            raw_name = row["raw_name"] or ""
            mapping = upsert_product_mapping(conn, raw_name)
            counts["products_seen"] += 1
            result = conn.execute(text("""
                UPDATE cve_products
                SET product_family = :product_family, product_category = :product_category, updated_at = :updated_at
                WHERE id = :id AND (product_family IS DISTINCT FROM :product_family OR product_category IS DISTINCT FROM :product_category)
            """), {"id": row["link_id"], "product_family": mapping.product_family, "product_category": mapping.product_category, "updated_at": utcnow()})
            counts["links_updated"] += result.rowcount or 0
            counts["mappings_upserted"] += 1
    return counts

if __name__ == "__main__":
    print(backfill())
