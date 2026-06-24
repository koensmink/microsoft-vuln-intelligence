from collections.abc import Iterator
from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db
from app.models import Cve, CveEnrichment, CveProduct, Product, Release
import app.api.routes as routes
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


def test_products_monthly_delta_counts_distinct_cves() -> None:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    with TestingSessionLocal() as db:
        current = Release(release_name="2026-Jun", release_date=datetime(2026, 6, 11))
        previous = Release(release_name="2026-May", release_date=datetime(2026, 5, 13))
        product_a = Product(product_id="p-a", name="Product A")
        product_b = Product(product_id="p-b", name="Product B")
        db.add_all([current, previous, product_a, product_b])
        db.flush()

        current_cve = Cve(cve_id="CVE-2026-0201", title="Current", release_id=current.id)
        previous_cve = Cve(cve_id="CVE-2026-0101", title="Previous", release_id=previous.id)
        db.add_all([current_cve, previous_cve])
        db.flush()
        db.add_all(
            [
                CveProduct(cve_id=current_cve.id, product_id=product_a.id, product_family="Windows", product_category="Operating Systems", severity="Critical"),
                CveProduct(cve_id=current_cve.id, product_id=product_b.id, product_family="Windows", product_category="Operating Systems", severity="Critical"),
                CveProduct(cve_id=previous_cve.id, product_id=product_a.id, product_family="Windows", product_category="Operating Systems", severity="Important"),
                CveEnrichment(cve_id=current_cve.id, source="kev", kev_known_exploited=True),
                CveEnrichment(cve_id=current_cve.id, source="epss", epss_score=0.25),
            ]
        )
        db.commit()

    def override_get_db() -> Iterator[Session]:
        with TestingSessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        default_response = client.get("/api/v1/products/monthly-delta")
        explicit_response = client.get(
            "/api/v1/products/monthly-delta",
            params={"current_release": "2026-Jun", "previous_release": "2026-May", "limit": 25},
        )
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert default_response.status_code == 200
    assert explicit_response.status_code == 200
    row = default_response.json()[0]
    assert row["product_family"] == "Windows"
    assert row["product_category"] == "Operating Systems"
    assert row["current_cve_count"] == 1
    assert row["previous_cve_count"] == 1
    assert row["delta_cve_count"] == 0
    assert row["delta_critical_count"] == 1
    assert row["delta_kev_count"] == 1
    assert row["delta_high_epss_count"] == 1
    assert row["delta_priority_score"] == 50
    assert explicit_response.json() == default_response.json()


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
        risk_response = client.get("/api/v1/products/risk-ranking")
        invalid_risk_limit_response = client.get("/api/v1/products/risk-ranking", params={"limit": 51})
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert stats_response.status_code == 200
    assert summary_response.status_code == 200
    assert categories_response.status_code == 200
    assert risk_response.status_code == 200
    assert invalid_risk_limit_response.status_code == 422

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

    risk_ranking = risk_response.json()
    assert risk_ranking[0]["product_family"] == "Windows"
    assert risk_ranking[0]["product_category"] == "Operating Systems"
    assert risk_ranking[0]["critical_count"] == 1
    assert risk_ranking[0]["kev_count"] == 1
    assert risk_ranking[0]["high_epss_count"] == 1
    assert risk_ranking[0]["average_cvss_score"] == 9.8
    assert risk_ranking[0]["risk_score"] == 69.6
    assert risk_ranking[0]["risk_level"] == "Low"


def test_ai_context_empty_and_missing_key_generate(monkeypatch) -> None:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    with TestingSessionLocal() as db:
        cve = Cve(cve_id="CVE-2026-9999", title="AI context test")
        db.add(cve)
        db.commit()

    def override_get_db() -> Iterator[Session]:
        with TestingSessionLocal() as db:
            yield db

    monkeypatch.setattr(settings, "ai_admin_api_key", None)
    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        empty_response = client.get("/api/v1/cves/CVE-2026-9999/ai-context")
        missing_key_response = client.post("/api/v1/cves/CVE-2026-9999/ai-context/generate")
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert empty_response.status_code == 404
    assert empty_response.json()["detail"] == "AI context not generated"
    assert missing_key_response.status_code == 503
    assert missing_key_response.json()["detail"] == "AI admin key is not configured"


def test_ai_context_generate_requires_valid_admin_key(monkeypatch) -> None:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    with TestingSessionLocal() as db:
        cve = Cve(cve_id="CVE-2026-9998", title="AI context admin test")
        db.add(cve)
        db.commit()

    def override_get_db() -> Iterator[Session]:
        with TestingSessionLocal() as db:
            yield db

    def fake_generate_with_openai(payload):
        return {
            "plain_summary": "Samenvatting.",
            "business_impact": "Impact.",
            "who_should_act": ["Beheerder"],
            "what_to_check": ["Controleer productdata"],
            "recommended_action": "Controleer en patch waar nodig.",
            "technical_context": "Technische context.",
            "confidence": "medium",
            "limitations": ["Beperkte brondata"],
            "how_to_check": ["Controleer of het product aanwezig is."],
            "powershell_checks": [
                {
                    "title": "Windows inventarisatie",
                    "command": "Get-ComputerInfo",
                    "explanation": "Toont basisinformatie over het systeem.",
                    "applies_to": "Windows",
                }
            ],
            "verification_notes": ["Gebruik officiële remediation-data voor patchstatus."],
        }

    monkeypatch.setattr(settings, "ai_admin_api_key", "secret")
    monkeypatch.setattr(routes, "generate_with_openai", fake_generate_with_openai)
    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        get_response = client.get("/api/v1/cves/CVE-2026-9998/ai-context")
        missing_response = client.post("/api/v1/cves/CVE-2026-9998/ai-context/generate")
        invalid_response = client.post(
            "/api/v1/cves/CVE-2026-9998/ai-context/generate",
            headers={"X-AI-Admin-Key": "wrong"},
        )
        valid_response = client.post(
            "/api/v1/cves/CVE-2026-9998/ai-context/generate",
            headers={"X-AI-Admin-Key": "secret"},
        )
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert get_response.status_code == 404
    assert get_response.json()["detail"] == "AI context not generated"
    assert missing_response.status_code == 403
    assert missing_response.json()["detail"] == "Invalid AI admin key"
    assert invalid_response.status_code == 403
    assert invalid_response.json()["detail"] == "Invalid AI admin key"
    assert valid_response.status_code == 200
    valid_body = valid_response.json()
    assert valid_body["plain_summary"] == "Samenvatting."
    assert valid_body["how_to_check"] == ["Controleer of het product aanwezig is."]
    assert valid_body["powershell_checks"][0]["command"] == "Get-ComputerInfo"
    assert valid_body["verification_notes"] == ["Gebruik officiële remediation-data voor patchstatus."]


def test_ai_context_batch_generate_requires_key_and_skips_cached(monkeypatch) -> None:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    with TestingSessionLocal() as db:
        release = Release(release_name="2026-Jun", release_date=datetime(2026, 6, 11))
        product = Product(product_id="p-batch", name="Batch Product")
        db.add_all([release, product])
        db.flush()
        cve = Cve(cve_id="CVE-2026-7777", title="Batch critical", release_id=release.id)
        db.add(cve)
        db.flush()
        db.add(CveProduct(cve_id=cve.id, product_id=product.id, severity="Critical"))
        db.commit()

    def override_get_db() -> Iterator[Session]:
        with TestingSessionLocal() as db:
            yield db

    calls = []

    def fake_generate_with_openai(payload):
        calls.append(payload["cve_id"])
        return {
            "plain_summary": "Samenvatting.",
            "business_impact": "Impact.",
            "who_should_act": ["Beheerder"],
            "what_to_check": ["Controleer productdata"],
            "recommended_action": "Controleer en patch waar nodig.",
            "technical_context": "Technische context.",
            "confidence": "medium",
            "limitations": ["Beperkte brondata"],
        }

    monkeypatch.setattr(settings, "ai_admin_api_key", "secret")
    monkeypatch.setattr(routes, "generate_with_openai", fake_generate_with_openai)
    app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(app)
        missing_response = client.post("/api/v1/ai-context/batch-generate")
        generated_response = client.post(
            "/api/v1/ai-context/batch-generate",
            headers={"X-AI-Admin-Key": "secret"},
        )
        skipped_response = client.post(
            "/api/v1/ai-context/batch-generate",
            headers={"X-AI-Admin-Key": "secret"},
        )
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)

    assert missing_response.status_code == 403
    assert generated_response.status_code == 200
    assert generated_response.json() == {
        "selected": 1,
        "generated": 1,
        "skipped": 0,
        "failed": 0,
        "failures": [],
    }
    assert skipped_response.status_code == 200
    assert skipped_response.json() == {
        "selected": 1,
        "generated": 0,
        "skipped": 1,
        "failed": 0,
        "failures": [],
    }
    assert calls == ["CVE-2026-7777"]
