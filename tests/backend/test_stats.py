from collections.abc import Iterator
from datetime import datetime, timedelta

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


def test_stats_timeseries_returns_release_level_points() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    with TestingSessionLocal() as db:
        product = Product(product_id="p-a", name="Product A")
        may = Release(release_name="2026-May", release_date=datetime(2026, 5, 13))
        jun = Release(release_name="2026-Jun", release_date=datetime(2026, 6, 10))
        db.add_all([product, may, jun])
        db.flush()

        cve_1 = Cve(cve_id="CVE-2026-1001", release_id=may.id)
        cve_2 = Cve(cve_id="CVE-2026-1002", release_id=may.id)
        cve_3 = Cve(cve_id="CVE-2026-1003", release_id=jun.id)
        db.add_all([cve_1, cve_2, cve_3])
        db.flush()

        db.add_all(
            [
                CveProduct(cve_id=cve_1.id, product_id=product.id, severity="Critical", cvss_base_score=9.8),
                CveProduct(cve_id=cve_2.id, product_id=product.id, severity="Important", cvss_base_score=7.2),
                CveProduct(cve_id=cve_3.id, product_id=product.id, severity="Critical"),
                CveEnrichment(cve_id=cve_1.id, source="epss", epss_score=0.25),
                CveEnrichment(cve_id=cve_1.id, source="kev", kev_known_exploited=True),
                CveEnrichment(cve_id=cve_3.id, source="nvd", cvss_score=8.0),
            ]
        )
        db.commit()

    def override_get_db() -> Iterator[Session]:
        with TestingSessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = TestClient(app).get("/api/v1/stats/timeseries")
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert response.status_code == 200
    assert response.json() == [
        {
            "label": "2026-May",
            "release_date": "2026-05-13T00:00:00",
            "total_cves": 2,
            "critical_cves": 1,
            "high_epss_count": 1,
            "kev_count": 1,
            "average_cvss_score": 8.5,
        },
        {
            "label": "2026-Jun",
            "release_date": "2026-06-10T00:00:00",
            "total_cves": 1,
            "critical_cves": 1,
            "high_epss_count": 0,
            "kev_count": 0,
            "average_cvss_score": 8.0,
        },
    ]


def test_stats_timeseries_excludes_empty_releases_and_limits_to_latest_12() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    with TestingSessionLocal() as db:
        product = Product(product_id="p-a", name="Product A")
        db.add(product)
        db.flush()

        empty_old_release = Release(
            release_name="1999-Sep", release_date=datetime(1999, 9, 1)
        )
        db.add(empty_old_release)

        first_release_date = datetime(2025, 1, 14)
        for index in range(13):
            release = Release(
                release_name=f"2025-{index + 1:02d}",
                release_date=first_release_date + timedelta(days=index * 30),
            )
            db.add(release)
            db.flush()

            cve = Cve(cve_id=f"CVE-2025-{index + 1:04d}", release_id=release.id)
            db.add(cve)
            db.flush()
            db.add(
                CveProduct(
                    cve_id=cve.id,
                    product_id=product.id,
                    severity="Important",
                    cvss_base_score=7.0,
                )
            )

        db.commit()

    def override_get_db() -> Iterator[Session]:
        with TestingSessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = TestClient(app).get("/api/v1/stats/timeseries")
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert response.status_code == 200
    points = response.json()
    assert len(points) == 12
    assert points[0]["label"] == "2025-02"
    assert points[-1]["label"] == "2025-13"
    assert "1999-Sep" not in {point["label"] for point in points}
    assert all(point["total_cves"] > 0 for point in points)
    assert [point["release_date"] for point in points] == sorted(
        point["release_date"] for point in points
    )

