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
        if not isinstance(data.get(field), list):
            raise ValueError(f"OpenAI response missing required list field: {field}")

    allowed_confidence = {"low", "medium", "high"}
    if data.get("confidence") not in allowed_confidence:
        raise ValueError("OpenAI response has invalid confidence value")

    return data


def _messages(payload: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": (
                "Je bent een senior vulnerability analyst. "
                "Je vertaalt technische CVE-informatie naar begrijpelijke Nederlandse uitleg voor niet-security stakeholders. "
                "Gebruik uitsluitend de aangeleverde CVE-data. "
                "Verzin nooit exploitdetails, getroffen producten, mitigaties, workarounds, aanvalspaden of business impact. "
                "Maak geen aannames over de omgeving van de lezer. "
                "Als informatie ontbreekt, zeg dat expliciet. "
                "Claim alleen actieve uitbuiting als kev_known_exploited, exploited of publicly_disclosed dit ondersteunt. "
                "Noem KEV alleen als kev_known_exploited true is. "
                "Noem publieke bekendheid alleen als publicly_disclosed true is. "
                "Gebruik zakelijke, rustige taal. Geen marketingtaal. Geen sensatie. "
                "Schrijf op B1/B2-niveau, maar behoud technische juistheid. "
                "Geef uitsluitend geldige JSON terug. Geen markdown. Geen extra tekst."
            ),
        },
        {
            "role": "user",
            "content": (
                "Maak laagdrempelige context voor deze CVE. "
                "Gebruik exact deze JSON velden:\n"
                "{\n"
                '  "plain_summary": "Korte uitleg in gewone taal. Maximaal 3 zinnen.",\n'
                '  "business_impact": "Praktische betekenis voor een organisatie. Maximaal 3 zinnen.",\n'
                '  "who_should_act": ["Lijst met teams of rollen die waarschijnlijk moeten kijken, gebaseerd op productdata."],\n'
                '  "what_to_check": ["Concrete controlepunten op basis van de aangeleverde data. Geen verzonnen mitigaties."],\n'
                '  "recommended_action": "Kort advies op basis van severity, CVSS, EPSS, KEV, exploited en publicly_disclosed.",\n'
                '  "technical_context": "Korte uitleg van severity, CVSS, EPSS, KEV en disclosure-status.",\n'
                '  "confidence": "low | medium | high",\n'
                '  "limitations": ["Welke informatie ontbreekt of onzeker is."]\n'
                "}\n\n"
                "Regels voor interpretatie:\n"
                "- Als kev_known_exploited true is: benoem dat deze CVE in CISA KEV staat.\n"
                "- Als exploited true is: benoem dat uitbuiting is gemarkeerd in de brondata.\n"
                "- Als publicly_disclosed true is: benoem dat publieke bekendheid is gemarkeerd in de brondata.\n"
                "- Als EPSS ontbreekt: zeg dat exploitkans niet beschikbaar is.\n"
                "- Als CVSS ontbreekt: zeg dat technische ernstscore niet beschikbaar is.\n"
                "- Als description ontbreekt: zeg dat inhoudelijke beschrijving beperkt is.\n"
                "- Als affected_products leeg is: zeg dat getroffen producten niet bekend zijn in de beschikbare data.\n"
                "- Adviseer patchen of controleren, maar verzin geen specifieke KB's, registry keys, workarounds of configuratiestappen.\n\n"
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
        "temperature": 0.2,
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
