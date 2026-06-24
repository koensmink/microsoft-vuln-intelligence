import hashlib
import json
import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.models.entities import Cve, CveAiContext, CveProduct

logger = logging.getLogger(__name__)

REQUIRED_TEXT_FIELDS = [
    "plain_summary",
    "business_impact",
    "recommended_action",
    "technical_context",
    "confidence",
]
REQUIRED_LIST_FIELDS = ["who_should_act", "what_to_check", "limitations"]


def load_cve_for_ai(db: Session, cve_id: str) -> Cve | None:
    return (
        db.query(Cve)
        .options(
            joinedload(Cve.release),
            joinedload(Cve.product_links).joinedload(CveProduct.product),
            joinedload(Cve.remediations),
            joinedload(Cve.enrichments),
        )
        .filter(Cve.cve_id == cve_id)
        .first()
    )


def build_source_payload(cve: Cve) -> dict[str, Any]:
    return {
        "cve_id": cve.cve_id,
        "title": cve.title,
        "description": cve.description,
        "release_date": cve.release_date.isoformat() if cve.release_date else None,
        "release": cve.release.release_name if cve.release else None,
        "severity": cve.severity,
        "impact": cve.impact,
        "cvss_score": cve.cvss_score,
        "exploited": cve.exploited,
        "publicly_disclosed": cve.publicly_disclosed,
        "kev_known_exploited": cve.kev_known_exploited,
        "kev_due_date": cve.kev_due_date.isoformat() if cve.kev_due_date else None,
        "kev_vendor_project": cve.kev_vendor_project,
        "kev_product": cve.kev_product,
        "kev_required_action": cve.kev_required_action,
        "epss_score": cve.epss_score,
        "epss_percentile": cve.epss_percentile,
        "nvd_cvss_score": cve.nvd_cvss_score,
        "nvd_cvss_vector": cve.nvd_cvss_vector,
        "affected_products": [
            {
                "product": link.product.name if link.product else None,
                "product_id": link.product.product_id if link.product else None,
                "status": link.status,
                "severity": link.severity,
                "impact": link.impact,
                "cvss_base_score": link.cvss_base_score,
                "cvss_vector": link.cvss_vector,
                "exploited": link.exploited,
                "publicly_disclosed": link.publicly_disclosed,
                "product_family": link.product_family,
                "product_category": link.product_category,
            }
            for link in cve.product_links
        ],
        "remediations": [
            {
                "product": remediation.product.name if remediation.product else None,
                "type": remediation.remediation_type,
                "subtype": remediation.subtype,
                "description": remediation.description,
                "url": remediation.url,
            }
            for remediation in cve.remediations
        ],
    }


def source_hash(payload: dict[str, Any]) -> str:
    normalized = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_ai_context(data: dict[str, Any]) -> dict[str, Any]:
    for field in REQUIRED_TEXT_FIELDS:
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise ValueError(f"OpenAI response missing required field: {field}")

    for field in REQUIRED_LIST_FIELDS:
        value = data.get(field)

        if isinstance(value, list):
            continue

        if isinstance(value, str) and value.strip():
            data[field] = [value.strip()]
            continue

        if value is None:
            data[field] = []
            continue

        raise ValueError(f"OpenAI response missing required list field: {field}")

    confidence = data.get("confidence", "").strip().lower()
    allowed_confidence = {"low", "medium", "high"}
    if confidence not in allowed_confidence:
        raise ValueError("OpenAI response has invalid confidence value")
    data["confidence"] = confidence

    return data


def _messages(payload: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": (
                "Je bent een Microsoft security consultant die kwetsbaarheden uitlegt "
                "aan niet-technische gebruikers. "
                "De doelgroep bestaat uit IT-managers, projectmanagers, servicedeskmedewerkers, "
                "functioneel beheerders en management. "
                "Ga ervan uit dat de lezer geen kennis heeft van security-termen zoals "
                "CVSS, EPSS, KEV, privilege escalation, remote code execution, attack vector "
                "of remediation. "
                "Gebruik uitsluitend informatie uit de aangeleverde CVE-data. "
                "Verzin geen feiten, getroffen producten, exploitdetails, mitigaties, workarounds "
                "of specifieke patchnummers die niet in de data staan. "
                "Als informatie ontbreekt, benoem dat expliciet. "
                "Vertaal technische informatie naar begrijpelijke taal. "
                "Leg uit waarom iemand dit moet weten en wat er praktisch gedaan moet worden. "
                "Noem CVSS, EPSS of KEV alleen als je ook uitlegt wat dat betekent. "
                "Gebruik korte, duidelijke zinnen. "
                "Vermijd security-jargon zoveel mogelijk. "
                "Geef uitsluitend geldige JSON terug."
            ),
        },
        {
            "role": "user",
            "content": (
                "Maak een begrijpelijke uitleg voor deze CVE. "
                "Gebruik exact deze JSON velden:\n"
                "plain_summary,\n"
                "business_impact,\n"
                "recommended_action,\n"
                "technical_context,\n"
                "confidence,\n"
                "who_should_act,\n"
                "what_to_check,\n"
                "limitations.\n\n"
                "Gebruik de velden als volgt:\n"
                "plain_summary = Leg in gewone taal uit wat er aan de hand is.\n"
                "business_impact = Beantwoord waarom dit belangrijk is, wat er kan gebeuren als we niets doen, "
                "en hoe relevant dit is voor een gemiddelde organisatie.\n"
                "recommended_action = Beschrijf de eerste concrete acties die een organisatie moet uitvoeren.\n"
                "technical_context = Leg technische details uit in begrijpelijke taal. Gebruik geen jargon zonder uitleg.\n"
                "who_should_act = Lijst van teams of rollen die waarschijnlijk verantwoordelijk zijn.\n"
                "what_to_check = Concrete controlepunten die iemand direct kan nalopen. "
                "Geef waar betrouwbaar mogelijk defensieve PowerShell-controles, maar verzin geen exploitchecks.\n"
                "limitations = Welke informatie ontbreekt waardoor onzekerheid bestaat.\n"
                "confidence moet uitsluitend zijn: low, medium of high.\n\n"
                "Belangrijk:\n"
                "- Geef altijd alle gevraagde velden terug.\n"
                "- who_should_act, what_to_check en limitations moeten altijd arrays zijn.\n"
                "- Gebruik [] als er geen informatie beschikbaar is.\n"
                "- Gebruik nooit een string voor arrayvelden.\n"
                "- Geef geen aanvalsinstructies of exploitstappen.\n"
                "- PowerShell mag alleen worden gebruikt voor defensieve verificatie, zoals versie-, update- of productcontrole.\n\n"
                "Schrijf alsof je een manager helpt begrijpen wat deze kwetsbaarheid betekent zonder security-achtergrond.\n\n"
                f"CVE-data: {json.dumps(payload, ensure_ascii=False, default=str)}"
            ),
        },
    ]


def generate_with_openai(payload: dict[str, Any]) -> dict[str, Any]:
    if not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured")

    body = {
        "model": settings.openai_model,
        "messages": _messages(payload),
        "response_format": {"type": "json_object"},
    }

    with httpx.Client(timeout=60) as client:
        response = client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.openai_api_key}"},
            json=body,
        )

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError:
        logger.error("OpenAI error response: %s", response.text)
        raise

    content = response.json()["choices"][0]["message"]["content"]
    return validate_ai_context(json.loads(content))


def upsert_ai_context(
    db: Session,
    cve: Cve,
    payload: dict[str, Any],
    source_hash_value: str,
) -> CveAiContext:
    existing = (
        db.query(CveAiContext)
        .filter(CveAiContext.cve_id == cve.id, CveAiContext.language == "nl")
        .first()
    )

    context = existing or CveAiContext(cve_id=cve.id, language="nl")
    context.model = settings.openai_model
    context.source_hash = source_hash_value

    for field in REQUIRED_TEXT_FIELDS + REQUIRED_LIST_FIELDS:
        setattr(context, field, payload[field])

    if not existing:
        db.add(context)

    db.commit()
    db.refresh(context)
    return context
