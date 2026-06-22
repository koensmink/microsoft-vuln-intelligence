from collections.abc import Iterator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.models import Cve, CveEnrichment, CveProduct, Product
from backend.app.main import app


def test_health():
    client = TestClient(app)
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_list_cves_filters_by_impact() -> None:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    with TestingSessionLocal() as db:
        product = Product(product_id="p-a", name="Product A")
        db.add(product)
        db.flush()

        rce = Cve(cve_id="CVE-2026-0001", title="RCE")
        eop = Cve(cve_id="CVE-2026-0002", title="EOP")
        unknown_text = Cve(cve_id="CVE-2026-0003", title="Unknown text")
        unknown_null = Cve(cve_id="CVE-2026-0004", title="Unknown null")
        db.add_all([rce, eop, unknown_text, unknown_null])
        db.flush()

        db.add_all(
            [
                CveProduct(
                    cve_id=rce.id, product_id=product.id, impact="Remote Code Execution"
                ),
                CveProduct(
                    cve_id=eop.id,
                    product_id=product.id,
                    impact="Elevation of Privilege",
                ),
                CveProduct(
                    cve_id=unknown_text.id, product_id=product.id, impact="Unknown"
                ),
                CveProduct(cve_id=unknown_null.id, product_id=product.id),
            ]
        )
        db.commit()

    def override_get_db() -> Iterator[Session]:
        with TestingSessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        rce_response = client.get(
            "/api/v1/cves", params={"impact": "Remote Code Execution"}
        )
        eop_response = client.get(
            "/api/v1/cves", params={"impact": "Elevation of Privilege"}
        )
        unknown_response = client.get("/api/v1/cves", params={"impact": "Unknown"})
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert rce_response.status_code == 200
    assert [cve["impact"] for cve in rce_response.json()] == ["Remote Code Execution"]
    assert [cve["cve_id"] for cve in rce_response.json()] == ["CVE-2026-0001"]

    assert eop_response.status_code == 200
    assert [cve["impact"] for cve in eop_response.json()] == ["Elevation of Privilege"]
    assert [cve["cve_id"] for cve in eop_response.json()] == ["CVE-2026-0002"]

    assert unknown_response.status_code == 200
    assert {cve["cve_id"] for cve in unknown_response.json()} == {
        "CVE-2026-0003",
        "CVE-2026-0004",
    }
    assert {cve["impact"] for cve in unknown_response.json()} == {"Unknown", None}


def test_product_rollup_endpoints_return_truthy_counts() -> None:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    with TestingSessionLocal() as db:
        product = Product(product_id="p-a", name="Product A")
        db.add(product)
        db.flush()

        cve = Cve(cve_id="CVE-2026-0101", title="Critical KEV high EPSS")
        db.add(cve)
        db.flush()
        db.add_all(
            [
                CveProduct(
                    cve_id=cve.id,
                    product_id=product.id,
                    product_family="Windows",
                    product_category="Operating Systems",
                    severity="Critical",
                    cvss_base_score=9.8,
                ),
                CveEnrichment(cve_id=cve.id, source="kev", kev_known_exploited=True),
                CveEnrichment(cve_id=cve.id, source="epss", epss_score=0.25),
            ]
        )
        db.commit()

    def override_get_db() -> Iterator[Session]:
        with TestingSessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        stats_response = client.get("/api/v1/stats")
        summary_response = client.get("/api/v1/products/summary")
        categories_response = client.get("/api/v1/products/categories")
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert stats_response.status_code == 200
    assert summary_response.status_code == 200
    assert categories_response.status_code == 200

    stats = stats_response.json()
    assert stats["top_product_families"][0]["critical_count"] == 1
    assert stats["top_product_families"][0]["kev_count"] == 1
    assert stats["top_product_families"][0]["high_epss_count"] == 1

    summary = summary_response.json()
    assert summary[0]["product_family"] == "Windows"
    assert summary[0]["product_category"] == "Operating Systems"
    assert summary[0]["critical_count"] == 1
    assert summary[0]["kev_count"] == 1
    assert summary[0]["high_epss_count"] == 1

    categories = categories_response.json()
    assert categories[0]["product_category"] == "Operating Systems"
    assert categories[0]["critical_count"] == 1
    assert categories[0]["kev_count"] == 1
    assert categories[0]["high_epss_count"] == 1
