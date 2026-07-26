import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes
from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.entities import Cve, CveAiContext
from app.schemas.entities import PowerShellCheckOut
from app.services.ai_context import validate_ai_context


def ai_payload(applies_to=...):
    check = {
        "title": "Controle",
        "command": "Get-HotFix",
        "explanation": "Controleer updates.",
    }
    if applies_to is not ...:
        check["applies_to"] = applies_to
    return {
        "plain_summary": "Samenvatting",
        "business_impact": "Impact",
        "recommended_action": "Actie",
        "technical_context": "Context",
        "confidence": "high",
        "who_should_act": ["Beheer"],
        "what_to_check": ["Updates"],
        "limitations": [],
        "how_to_check": [],
        "powershell_checks": [check],
        "verification_notes": [],
    }


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
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


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            ["Windows 10", "Windows 11", "Windows Server"],
            ["Windows 10", "Windows 11", "Windows Server"],
        ),
        ("Windows 11", ["Windows 11"]),
        (None, []),
        (..., []),
        (["Windows 11", 42, None], ["Windows 11"]),
    ],
)
def test_validate_ai_context_normalizes_applies_to(value, expected):
    result = validate_ai_context(ai_payload(value))

    assert result["powershell_checks"][0]["applies_to"] == expected


def test_powershell_check_schema_normalizes_legacy_values():
    base = {"title": "Controle", "command": "Get-HotFix", "explanation": "Uitleg"}

    assert PowerShellCheckOut(**base).applies_to == []
    assert PowerShellCheckOut(**base, applies_to=None).applies_to == []
    assert PowerShellCheckOut(**base, applies_to="Windows").applies_to == ["Windows"]
    assert PowerShellCheckOut(
        **base, applies_to=["Windows", 3, None]
    ).applies_to == ["Windows"]


def add_context(db, cve, applies_to):
    context = CveAiContext(
        cve_id=cve.id,
        language="nl",
        model="test-model",
        plain_summary="Samenvatting",
        business_impact="Impact",
        who_should_act=["Beheer"],
        what_to_check=["Updates"],
        recommended_action="Actie",
        technical_context="Context",
        confidence="high",
        limitations=[],
        how_to_check=[],
        powershell_checks=ai_payload(applies_to)["powershell_checks"],
        verification_notes=[],
        source_hash="hash",
    )
    db.add(context)
    db.commit()
    return context


def test_get_existing_context_serializes_list_applies_to(client, db):
    cve = Cve(cve_id="CVE-2026-1000", title="Test")
    db.add(cve)
    db.commit()
    add_context(db, cve, ["Windows 10", "Windows 11", "Windows Server"])

    response = client.get("/api/v1/cves/CVE-2026-1000/ai-context")

    assert response.status_code == 200
    assert response.json()["powershell_checks"][0]["applies_to"] == [
        "Windows 10",
        "Windows 11",
        "Windows Server",
    ]


def test_generate_context_serializes_applies_to(client, db, monkeypatch):
    cve = Cve(cve_id="CVE-2026-1001", title="Test")
    db.add(cve)
    db.commit()
    monkeypatch.setattr(settings, "ai_admin_api_key", "secret")
    monkeypatch.setattr(
        routes,
        "generate_with_openai",
        lambda payload: validate_ai_context(ai_payload(["Windows", "Windows Server"])),
    )

    response = client.post(
        "/api/v1/cves/CVE-2026-1001/ai-context/generate",
        headers={"X-AI-Admin-Key": "secret"},
    )

    assert response.status_code == 200
    assert response.json()["powershell_checks"][0]["applies_to"] == [
        "Windows",
        "Windows Server",
    ]
