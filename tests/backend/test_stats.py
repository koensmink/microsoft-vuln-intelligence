from collections.abc import Iterator
from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.models import Cve, CveEnrichment, CveProduct, Product, Release
from backend.app.main import app


def test_stats_uses_cve_level_metric_semantics() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    with TestingSessionLocal() as db:
        product_a = Product(product_id="p-a", name="Product A")
        product_b = Product(product_id="p-b", name="Product B")
        db.add_all([product_a, product_b])
        db.flush()

        cve_1 = Cve(cve_id="CVE-2026-0001", title="Critical with duplicate product mappings")
        cve_2 = Cve(cve_id="CVE-2026-0002", title="NVD fallback only")
        cve_3 = Cve(cve_id="CVE-2026-0003", title="Unknown severity")
        db.add_all([cve_1, cve_2, cve_3])
        db.flush()

        db.add_all(
            [
                CveProduct(cve_id=cve_1.id, product_id=product_a.id, severity="Critical", impact="Remote Code Execution", cvss_base_score=9.8),
                CveProduct(cve_id=cve_1.id, product_id=product_b.id, severity="Critical", impact="Remote Code Execution", cvss_base_score=9.1),
                CveProduct(cve_id=cve_2.id, product_id=product_a.id, severity="Important"),
                CveProduct(cve_id=cve_3.id, product_id=product_a.id),
                CveEnrichment(cve_id=cve_1.id, source="epss", epss_score=0.337, epss_percentile=0.9),
                CveEnrichment(cve_id=cve_1.id, source="kev", kev_known_exploited=True),
                CveEnrichment(cve_id=cve_2.id, source="epss", epss_score=0.175, epss_percentile=0.8),
                CveEnrichment(cve_id=cve_2.id, source="nvd", cvss_score=7.5),
            ]
        )
        db.commit()

    def override_get_db() -> Iterator[Session]:
        with TestingSessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = TestClient(app).get("/api/v1/stats")
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert response.status_code == 200
    stats = response.json()
    assert stats["total_cves"] == 3
    assert sum(bucket["count"] for bucket in stats["cves_by_severity"]) == stats["total_cves"]
    assert stats["count_by_severity"] == {"Critical": 1, "Important": 1, "Unknown": 1}
    assert stats["average_cvss_score"] == (9.8 + 7.5) / 2
    assert stats["epss_enriched_cves"] == 2
    assert stats["nvd_enriched_cves"] == 1
    assert stats["total_kev_vulnerabilities"] == 1
    assert stats["impact_known_cves"] == 1


def test_stats_latest_release_uses_max_release_date_not_release_name_sort() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    with TestingSessionLocal() as db:
        db.add_all(
            [
                Release(release_name="2026-May", release_date=datetime(2026, 5, 13)),
                Release(release_name="2026-Jun", release_date=datetime(2026, 6, 10)),
            ]
        )
        db.commit()

    def override_get_db() -> Iterator[Session]:
        with TestingSessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = TestClient(app).get("/api/v1/stats")
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert response.status_code == 200
    assert response.json()["latest_release"] == "2026-Jun"
