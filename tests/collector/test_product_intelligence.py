from datetime import datetime, timezone

from sqlalchemy import create_engine, text

from app.db.base import Base
from app import models  # noqa: F401
from collector.app import sync
from collector.app.product_intelligence import map_product_name
from collector import backfill_product_intelligence


def test_product_name_classifier_returns_meaningful_microsoft_families() -> None:
    examples = {
        "Windows Server 2025": "Windows Server",
        "Dynamics 365 Sales": "Dynamics 365",
        "Microsoft Office LTSC": "Microsoft Office",
        "Azure Kubernetes Service": "Azure Kubernetes Service",
    }

    for raw_name, expected_family in examples.items():
        assert map_product_name(raw_name).product_family == expected_family


def test_sync_maps_products_from_persisted_product_name() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    parsed = {
        "release": {"release_name": "2026-Jun"},
        "products": {
            "p-win": {"product_id": "p-win", "name": "Windows Server 2025", "cpe": None, "family": None},
        },
        "cves": [
            {
                "cve_id": "CVE-2026-0001",
                "products": {"p-win": {"name": "Ignored Transient Name"}},
                "product_data": {"p-win": {"severity": "Critical"}},
            }
        ],
    }

    with engine.begin() as conn:
        sync.sync_parsed_release(conn, parsed)
        row = conn.execute(
            text(
                """
                SELECT cp.product_family, cp.product_category, pm.raw_name
                FROM cve_products cp
                JOIN products p ON p.id = cp.product_id
                JOIN product_mappings pm ON pm.raw_name = p.name
                """
            )
        ).mappings().one()

    assert row["product_family"] == "Windows Server"
    assert row["product_category"] == "Operating System"
    assert row["raw_name"] == "Windows Server 2025"


def test_backfill_joins_cve_products_to_products_and_is_idempotent(tmp_path) -> None:
    db_path = tmp_path / "product-intelligence.db"
    database_url = f"sqlite+pysqlite:///{db_path}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)

    with engine.begin() as conn:
        now = datetime.now(timezone.utc)
        product_id = conn.execute(
            text("INSERT INTO products (product_id, name, created_at, updated_at) VALUES ('p-azure', 'Azure Kubernetes Service', :now, :now) RETURNING id"),
            {"now": now},
        ).scalar_one()
        cve_id = conn.execute(text("INSERT INTO cves (cve_id, created_at, updated_at) VALUES ('CVE-2026-0002', :now, :now) RETURNING id"), {"now": now}).scalar_one()
        conn.execute(
            text("INSERT INTO cve_products (cve_id, product_id, exploited, publicly_disclosed, created_at, updated_at) VALUES (:cve_id, :product_id, 0, 0, :now, :now)"),
            {"cve_id": cve_id, "product_id": product_id, "now": now},
        )

    backfill_product_intelligence.DATABASE_URL = database_url
    first = backfill_product_intelligence.backfill()
    second = backfill_product_intelligence.backfill()

    with engine.begin() as conn:
        counts = conn.execute(
            text(
                """
                SELECT
                    count(cp.product_family) AS family_count,
                    count(cp.product_category) AS category_count,
                    (SELECT count(*) FROM product_mappings) AS mapping_count
                FROM cve_products cp
                """
            )
        ).mappings().one()

    assert first["links_updated"] == 1
    assert second["links_updated"] == 0
    assert counts["family_count"] > 0
    assert counts["category_count"] > 0
    assert counts["mapping_count"] > 0
