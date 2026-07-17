from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.entities import Cve, CveEnrichment, CveProduct, Product, Release, SyncRun
from app.services.intelligence_summary import calculate_priority, get_data_quality, get_prioritized_cves, get_release_summary, get_system_status


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


@pytest.fixture
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def add_cve(db, release, cve_id, products=(), enrichments=()):
    cve = Cve(cve_id=cve_id, title=f"Title {cve_id}", release=release)
    db.add(cve)
    db.flush()
    for index, values in enumerate(products):
        product = Product(product_id=f"{cve_id}-{index}", name=f"Product {index}")
        db.add(product)
        db.flush()
        db.add(CveProduct(cve_id=cve.id, product_id=product.id, **values))
    for values in enrichments:
        db.add(CveEnrichment(cve_id=cve.id, **values))
    db.commit()
    return cve


def test_empty_database_and_zero_division(db):
    assert get_system_status(db)["status"] == "degraded"
    quality = get_data_quality(db)
    assert quality["total_cves"] == 0
    assert all(quality[key]["percentage"] == 0.0 for key in quality if key != "total_cves")


def test_status_without_release_or_sync_and_stale_data(db):
    db.add(SyncRun(started_at=datetime(2026, 1, 1), finished_at=datetime(2026, 1, 1), status="success", records_processed=2))
    db.commit()
    status = get_system_status(db, now=datetime(2026, 1, 4))
    assert status["latest_release"] is None
    assert status["last_sync_status"] == "success"
    assert status["data_freshness_hours"] == 72.0
    assert status["status"] == "degraded"

    db.query(SyncRun).delete()
    release = Release(release_name="2026-Jan", release_date=datetime(2026, 1, 13), last_synced_at=datetime(2026, 1, 13))
    db.add(release)
    db.commit()
    status = get_system_status(db, now=datetime(2026, 1, 14))
    assert status["last_sync_status"] is None
    assert status["last_successful_sync"] is None
    assert status["status"] == "healthy"


def test_failed_latest_sync_degrades_status(db):
    now = datetime.utcnow()
    db.add_all([
        Release(release_name="2026-Jul", release_date=now, last_synced_at=now),
        SyncRun(started_at=now, status="failed", records_processed=0),
    ])
    db.commit()
    assert get_system_status(db, now=now)["status"] == "degraded"


def test_data_quality_counts_each_cve_once_and_applies_definitions(db):
    release = Release(release_name="2026-Jul", release_date=datetime(2026, 7, 14))
    db.add(release)
    db.commit()
    add_cve(db, release, "CVE-2026-1", products=[
        {"severity": "Low", "product_family": "Other Microsoft Product", "product_category": "Unknown"},
        {"severity": "Critical", "product_family": " Windows ", "product_category": " OS "},
    ], enrichments=[
        {"source": "EPSS", "epss_score": 0.2},
        {"source": "NvD", "cvss_vector": "CVSS:3.1/..."},
    ])
    add_cve(db, release, "CVE-2026-2", products=[
        {"severity": "Important", "product_family": "Other Microsoft Product", "product_category": "Unknown"},
    ], enrichments=[{"source": "nvd", "cvss_vector": "   "}])
    quality = get_data_quality(db)
    assert quality["total_cves"] == 2
    assert quality["epss_coverage"]["covered"] == 1
    assert quality["nvd_coverage"]["covered"] == 1
    assert quality["product_classification"]["covered"] == 1


@pytest.mark.parametrize("epss,expected,reason", [
    (0.009, 0, None),
    (0.01, 10, "EPSS probability of 1% or higher"),
    (0.10, 20, "EPSS probability of 10% or higher"),
])
def test_priority_epss_boundaries(epss, expected, reason):
    score, level, reasons = calculate_priority(kev=False, exploited=False, publicly_disclosed=False, severity="Low", cvss_score=None, epss_score=epss)
    assert score == expected
    assert level == "routine"
    assert reasons == ([reason] if reason else [])


def test_priority_cap_levels_and_unique_component_reasons():
    score, level, reasons = calculate_priority(kev=True, exploited=True, publicly_disclosed=True, severity="Critical", cvss_score=9.8, epss_score=0.10)
    assert (score, level) == (100, "immediate")
    assert len(reasons) == len(set(reasons)) == 6
    assert calculate_priority(kev=True, exploited=False, publicly_disclosed=False, severity="Low", cvss_score=None, epss_score=None)[:2] == (40, "high")
    assert calculate_priority(kev=False, exploited=True, publicly_disclosed=True, severity="Low", cvss_score=None, epss_score=None)[:2] == (45, "high")
    assert calculate_priority(kev=True, exploited=False, publicly_disclosed=True, severity="Low", cvss_score=None, epss_score=0.10)[:2] == (70, "immediate")
    assert calculate_priority(kev=True, exploited=True, publicly_disclosed=False, severity="Low", cvss_score=None, epss_score=None)[:2] == (75, "immediate")


def test_prioritized_consolidation_sorting_and_filters(db):
    july = Release(release_name="2026-Jul", release_date=datetime(2026, 7, 14))
    june = Release(release_name="2026-Jun", release_date=datetime(2026, 6, 10))
    db.add_all([july, june])
    db.commit()
    add_cve(db, july, "CVE-2026-2", products=[
        {"severity": "Important", "cvss_base_score": 9.0, "product_family": "Zeta", "product_category": "Server"},
        {"severity": "Critical", "cvss_base_score": 8.0, "product_family": " Windows ", "product_category": " OS "},
    ], enrichments=[{"source": "epss", "epss_score": 0.10}])
    add_cve(db, july, "CVE-2026-3", products=[
        {"severity": "Critical", "cvss_base_score": 9.0, "product_family": "Windows", "product_category": "OS"},
    ], enrichments=[{"source": "epss", "epss_score": 0.10}])
    add_cve(db, june, "CVE-2026-1", products=[{"severity": "Low", "product_family": "Office", "product_category": "Apps"}])

    rows = get_prioritized_cves(db, release="2026-Jul", product_family="windows", product_category="os")
    assert [row["cve_id"] for row in rows] == ["CVE-2026-3", "CVE-2026-2"]
    assert rows[1]["severity"] == "Critical"
    assert rows[1]["cvss_score"] == 9.0
    assert [row["cve_id"] for row in get_prioritized_cves(db, priority="high")] == ["CVE-2026-3", "CVE-2026-2"]
    assert [row["cve_id"] for row in get_prioritized_cves(db, limit=1, offset=1)] == ["CVE-2026-2"]


def test_release_summary_chronology_and_deltas(db):
    oldest = Release(release_name="2099-Zzz", release_date=datetime(2026, 1, 1))
    previous = Release(release_name="2000-Aaa", release_date=datetime(2026, 2, 1))
    current = Release(release_name="2026-Mar", release_date=datetime(2026, 3, 1))
    db.add_all([oldest, previous, current])
    db.commit()
    add_cve(db, previous, "CVE-2026-1", products=[{"severity": "Low", "product_family": "Office", "product_category": "Apps"}])
    add_cve(db, current, "CVE-2026-2", products=[{"severity": "Critical", "product_family": "Windows", "product_category": "OS"}])
    summary = get_release_summary(db, "2026-Mar")
    assert summary["previous_release"] == "2000-Aaa"
    assert summary["cve_delta"] == 0
    assert summary["critical_delta"] == 1
    first = get_release_summary(db, "2099-Zzz")
    assert first["previous_release"] is first["cve_delta"] is first["critical_delta"] is None
    assert get_release_summary(db, "missing") is None


def test_routes_validation_404_and_smoke(client):
    for path in ("/api/v1/system/status", "/api/v1/system/data-quality", "/api/v1/cves/prioritized"):
        assert client.get(path).status_code == 200
    assert client.get("/api/v1/releases/missing/summary").status_code == 404
    assert client.get("/api/v1/cves/prioritized?limit=0").status_code == 422
    assert client.get("/api/v1/cves/prioritized?limit=101").status_code == 422
    assert client.get("/api/v1/cves/prioritized?offset=-1").status_code == 422
    assert client.get("/api/v1/cves/prioritized?priority=urgent").status_code == 422


def test_existing_endpoint_smoke(client):
    for path in ("/api/v1/health", "/api/v1/stats", "/api/v1/cves?limit=1", "/api/v1/releases", "/api/v1/products/summary?limit=1"):
        assert client.get(path).status_code == 200
