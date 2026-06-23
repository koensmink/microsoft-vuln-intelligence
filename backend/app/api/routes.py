from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.db.session import get_db
from app.services.ai_context import build_source_payload, generate_with_openai, load_cve_for_ai, source_hash, upsert_ai_context
from app.models import AffectedProduct, Cve, Product, ProductMapping, Release
from app.models.entities import CveAiContext, CveEnrichment, CveProduct
from app.schemas import (
    CveAiContextOut,
    CveDetailOut,
    CveEnrichmentOut,
    CveOut,
    ProductCategoryOut,
    ProductMappingOut,
    ProductMonthlyDeltaOut,
    ProductOut,
    ProductRiskRankingOut,
    ProductSummaryOut,
    ReleaseOut,
    StatsOut,
    StatsTimeseriesPointOut,
    SyncRequest,
)

router = APIRouter(prefix="/api/v1")


def require_ai_admin_key(x_ai_admin_key: str | None = Header(default=None, alias="X-AI-Admin-Key")) -> None:
    if not settings.ai_admin_api_key:
        raise HTTPException(status_code=503, detail="AI admin key is not configured")
    if x_ai_admin_key != settings.ai_admin_api_key:
        raise HTTPException(status_code=403, detail="Invalid AI admin key")


def _filtered_cve_ids_subquery(release: str | None, severity: str | None, kev: bool | None, min_epss: float | None):
    stmt = select(Cve.id)
    if release:
        stmt = stmt.join(Release).where(Release.release_name == release)
    if severity:
        stmt = stmt.where(Cve.product_links.any(CveProduct.severity == severity))
    if kev is not None:
        kev_clause = Cve.enrichments.any((CveEnrichment.source == "kev") & (CveEnrichment.kev_known_exploited.is_(True)))
        stmt = stmt.where(kev_clause if kev else ~kev_clause)
    if min_epss is not None:
        stmt = stmt.where(Cve.enrichments.any((CveEnrichment.source == "epss") & (CveEnrichment.epss_score >= min_epss)))
    return stmt.subquery()


def _product_rollup(db: Session, group_fields: list, release: str | None = None, severity: str | None = None, kev: bool | None = None, min_epss: float | None = None, limit: int | None = 20):
    cve_ids = _filtered_cve_ids_subquery(release, severity, kev, min_epss)
    cvss_value = func.max(func.coalesce(CveProduct.cvss_base_score, CveEnrichment.cvss_score))
    rows = db.execute(
        select(
            *group_fields,
            Cve.id.label("cve_pk"),
            func.max(case((CveProduct.severity == "Critical", 1), else_=0)).label(
                "is_critical"
            ),
            func.max(
                case((CveEnrichment.kev_known_exploited.is_(True), 1), else_=0)
            ).label("is_kev"),
            func.max(case((CveEnrichment.epss_score >= 0.10, 1), else_=0)).label(
                "is_high_epss"
            ),
            cvss_value.label("cvss_score"),
        )
        .select_from(CveProduct)
        .join(Cve)
        .outerjoin(Cve.enrichments)
        .where(Cve.id.in_(select(cve_ids.c.id)))
        .group_by(*group_fields, Cve.id)
    ).all()
    grouped = {}
    for row in rows:
        key = tuple(row[i] or "Unknown" for i in range(len(group_fields)))
        item = grouped.setdefault(key, {"cves": set(), "critical": 0, "kev": 0, "epss": 0, "scores": []})
        item["cves"].add(row.cve_pk)
        item["critical"] += int(bool(row.is_critical))
        item["kev"] += int(bool(row.is_kev))
        item["epss"] += int(bool(row.is_high_epss))
        if row.cvss_score is not None:
            item["scores"].append(float(row.cvss_score))
    results = []
    for key, item in grouped.items():
        result = {
            "cve_count": len(item["cves"]),
            "critical_count": item["critical"],
            "kev_count": item["kev"],
            "high_epss_count": item["epss"],
            "average_cvss_score": sum(item["scores"]) / len(item["scores"]) if item["scores"] else None,
        }
        if len(key) == 2:
            result.update({"product_family": key[0], "product_category": key[1]})
        else:
            result.update({"product_category": key[0]})
        results.append(result)
    results.sort(key=lambda item: item["cve_count"], reverse=True)
    return results[:limit] if limit else results


def _latest_release_pair(db: Session, current_release: str | None, previous_release: str | None):
    if current_release and previous_release:
        return current_release, previous_release

    releases = db.execute(
        select(Release.release_name)
        .where(Release.release_date.is_not(None))
        .order_by(Release.release_date.desc(), Release.release_name.desc())
    ).scalars().all()
    if len(releases) < 2:
        return None, None

    current = current_release or releases[0]
    if current not in releases:
        return None, None

    if previous_release:
        return current, previous_release

    current_index = releases.index(current)
    if current_index + 1 >= len(releases):
        return None, None
    return current, releases[current_index + 1]


def _product_release_counts(db: Session, release_name: str):
    rows = db.execute(
        select(
            func.coalesce(CveProduct.product_family, "Unknown").label("product_family"),
            func.coalesce(CveProduct.product_category, "Unknown").label("product_category"),
            Cve.id.label("cve_pk"),
            func.max(case((CveProduct.severity == "Critical", 1), else_=0)).label("is_critical"),
            func.max(case((CveEnrichment.kev_known_exploited.is_(True), 1), else_=0)).label("is_kev"),
            func.max(case((CveEnrichment.epss_score >= 0.10, 1), else_=0)).label("is_high_epss"),
        )
        .select_from(CveProduct)
        .join(Cve)
        .join(Release)
        .outerjoin(Cve.enrichments)
        .where(Release.release_name == release_name)
        .group_by(CveProduct.product_family, CveProduct.product_category, Cve.id)
    ).all()
    counts = {}
    for row in rows:
        key = (row.product_family or "Unknown", row.product_category or "Unknown")
        item = counts.setdefault(key, {"cves": set(), "critical": 0, "kev": 0, "epss": 0})
        item["cves"].add(row.cve_pk)
        item["critical"] += int(bool(row.is_critical))
        item["kev"] += int(bool(row.is_kev))
        item["epss"] += int(bool(row.is_high_epss))
    return counts


def _product_monthly_delta(db: Session, current_release: str | None, previous_release: str | None, limit: int):
    current, previous = _latest_release_pair(db, current_release, previous_release)
    if not current or not previous:
        return []

    current_counts = _product_release_counts(db, current)
    previous_counts = _product_release_counts(db, previous)
    keys = set(current_counts) | set(previous_counts)
    rows = []
    empty = {"cves": set(), "critical": 0, "kev": 0, "epss": 0}
    for product_family, product_category in keys:
        current_item = current_counts.get((product_family, product_category), empty)
        previous_item = previous_counts.get((product_family, product_category), empty)
        current_cve_count = len(current_item["cves"])
        previous_cve_count = len(previous_item["cves"])
        delta_cve_count = current_cve_count - previous_cve_count
        delta_critical_count = current_item["critical"] - previous_item["critical"]
        delta_kev_count = current_item["kev"] - previous_item["kev"]
        delta_high_epss_count = current_item["epss"] - previous_item["epss"]
        delta_priority_score = (
            delta_cve_count
            + (delta_critical_count * 10)
            + (delta_kev_count * 25)
            + (delta_high_epss_count * 15)
        )
        rows.append({
            "product_family": product_family,
            "product_category": product_category,
            "current_release": current,
            "previous_release": previous,
            "current_cve_count": current_cve_count,
            "previous_cve_count": previous_cve_count,
            "delta_cve_count": delta_cve_count,
            "current_critical_count": current_item["critical"],
            "previous_critical_count": previous_item["critical"],
            "delta_critical_count": delta_critical_count,
            "current_kev_count": current_item["kev"],
            "previous_kev_count": previous_item["kev"],
            "delta_kev_count": delta_kev_count,
            "current_high_epss_count": current_item["epss"],
            "previous_high_epss_count": previous_item["epss"],
            "delta_high_epss_count": delta_high_epss_count,
            "delta_priority_score": delta_priority_score,
        })
    rows.sort(key=lambda item: item["delta_priority_score"], reverse=True)
    return rows[:limit]


def _risk_level(risk_score: float) -> str:
    if risk_score >= 250:
        return "Critical"
    if risk_score >= 150:
        return "High"
    if risk_score >= 75:
        return "Medium"
    return "Low"


def _product_risk_ranking(db: Session, limit: int = 10):
    rows = _product_rollup(
        db,
        [
            func.coalesce(CveProduct.product_family, "Unknown"),
            func.coalesce(CveProduct.product_category, "Unknown"),
        ],
        limit=None,
    )
    for row in rows:
        average_cvss_score = row["average_cvss_score"] or 0
        risk_score = (
            (row["critical_count"] * 10)
            + (row["kev_count"] * 25)
            + (row["high_epss_count"] * 15)
            + (average_cvss_score * 2)
        )
        row["average_cvss_score"] = average_cvss_score
        row["risk_score"] = risk_score
        row["risk_level"] = _risk_level(risk_score)
    rows.sort(key=lambda item: item["risk_score"], reverse=True)
    return rows[:limit]


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/cves", response_model=list[CveOut])
def list_cves(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: str | None = None,
    severity: str | None = None,
    product: str | None = None,
    exploited: bool | None = None,
    publicly_disclosed: bool | None = None,
    release_name: str | None = None,
    kev_only: bool = False,
    min_epss_score: float | None = Query(None, ge=0, le=1),
    min_cvss_score: float | None = Query(None, ge=0, le=10),
    impact: str | None = None,
    product_family: str | None = None,
    product_category: str | None = None,
):
    stmt = select(Cve).options(
        joinedload(Cve.release),
        joinedload(Cve.product_links).joinedload(CveProduct.product),
        joinedload(Cve.enrichments),
    )

    if search:
        stmt = (
            stmt.outerjoin(Cve.product_links)
            .outerjoin(Product)
            .where(
                or_(
                    Cve.cve_id.ilike(f"%{search}%"),
                    Cve.title.ilike(f"%{search}%"),
                    Product.name.ilike(f"%{search}%"),
                )
            )
        )

    if severity:
        stmt = stmt.join(Cve.product_links).where(CveProduct.severity == severity)

    if impact:
        if impact == "Unknown":
            stmt = stmt.where(
                or_(
                    Cve.product_links.any(CveProduct.impact == "Unknown"),
                    ~Cve.product_links.any(
                        CveProduct.impact.is_not(None) & (CveProduct.impact != "")
                    ),
                )
            )
        else:
            stmt = stmt.where(Cve.product_links.any(CveProduct.impact == impact))

    if product_family:
        stmt = stmt.where(Cve.product_links.any(CveProduct.product_family == product_family))

    if product_category:
        stmt = stmt.where(Cve.product_links.any(CveProduct.product_category == product_category))

    if product:
        stmt = (
            stmt.join(Cve.product_links)
            .join(Product)
            .where(or_(Product.name.ilike(f"%{product}%"), Product.product_id == product))
        )

    if exploited is not None:
        stmt = stmt.join(Cve.product_links).where(CveProduct.exploited == exploited)

    if publicly_disclosed is not None:
        stmt = stmt.join(Cve.product_links).where(
            CveProduct.publicly_disclosed == publicly_disclosed
        )

    if release_name:
        stmt = stmt.join(Cve.release).where(Release.release_name == release_name)

    if kev_only:
        stmt = stmt.where(
            Cve.enrichments.any(
                (CveEnrichment.source == "kev")
                & (CveEnrichment.kev_known_exploited.is_(True))
            )
        )

    if min_epss_score is not None:
        stmt = stmt.where(
            Cve.enrichments.any(
                (CveEnrichment.source == "epss")
                & (CveEnrichment.epss_score >= min_epss_score)
            )
        )

    if min_cvss_score is not None:
        stmt = stmt.where(
            Cve.enrichments.any(
                (CveEnrichment.source == "nvd")
                & (CveEnrichment.cvss_score >= min_cvss_score)
            )
        )

    return db.scalars(stmt.order_by(Cve.cve_id).limit(limit).offset(offset)).unique().all()


@router.get("/enrichment/{cve_id}", response_model=list[CveEnrichmentOut])
def get_enrichment(cve_id: str, db: Session = Depends(get_db)):
    cve = db.scalar(
        select(Cve).where(Cve.cve_id == cve_id).options(joinedload(Cve.enrichments))
    )
    if not cve:
        raise HTTPException(404, "CVE not found")
    return cve.enrichments


@router.get("/cves/{cve_id}", response_model=CveDetailOut)
def get_cve(cve_id: str, db: Session = Depends(get_db)):
    cve = db.scalar(
        select(Cve)
        .where(Cve.cve_id == cve_id)
        .options(
            joinedload(Cve.release),
            joinedload(Cve.product_links).joinedload(CveProduct.product),
            joinedload(Cve.remediations),
            joinedload(Cve.enrichments),
        )
    )
    if not cve:
        raise HTTPException(404, "CVE not found")
    return cve


@router.get("/cves/{cve_id}/ai-context", response_model=CveAiContextOut)
def get_cve_ai_context(cve_id: str, db: Session = Depends(get_db)):
    cve = db.scalar(select(Cve).where(Cve.cve_id == cve_id))
    if not cve:
        raise HTTPException(404, "CVE not found")
    context = db.scalar(
        select(CveAiContext)
        .where(CveAiContext.cve_id == cve.id, CveAiContext.language == "nl")
        .order_by(CveAiContext.updated_at.desc())
    )
    if not context:
        raise HTTPException(404, "AI context not generated")
    return context


@router.post("/cves/{cve_id}/ai-context/generate", response_model=CveAiContextOut)
def generate_cve_ai_context(
    cve_id: str,
    force: bool = False,
    _: None = Depends(require_ai_admin_key),
    db: Session = Depends(get_db),
):
    cve = load_cve_for_ai(db, cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")

    payload = build_source_payload(cve)
    hash_value = source_hash(payload)
    cached = db.scalar(
        select(CveAiContext).where(
            CveAiContext.cve_id == cve.id,
            CveAiContext.language == "nl",
            CveAiContext.source_hash == hash_value,
        )
    )
    if cached and not force:
        return cached

    try:
        generated = generate_with_openai(payload)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        import logging
        logging.getLogger(__name__).exception("Failed to generate AI context for %s", cve_id)
        raise HTTPException(status_code=502, detail="Failed to generate AI context") from exc

    return upsert_ai_context(db, cve, generated, hash_value)


@router.get("/products/summary", response_model=list[ProductSummaryOut])
def products_summary(db: Session = Depends(get_db), release: str | None = None, severity: str | None = None, kev: bool | None = None, min_epss: float | None = Query(None, ge=0, le=1), limit: int = Query(20, ge=1, le=100)):
    return _product_rollup(db, [func.coalesce(CveProduct.product_family, "Unknown"), func.coalesce(CveProduct.product_category, "Unknown")], release, severity, kev, min_epss, limit)


@router.get("/products/categories", response_model=list[ProductCategoryOut])
def products_categories(db: Session = Depends(get_db), release: str | None = None, severity: str | None = None, kev: bool | None = None, min_epss: float | None = Query(None, ge=0, le=1), limit: int = Query(50, ge=1, le=100)):
    return _product_rollup(db, [func.coalesce(CveProduct.product_category, "Unknown")], release, severity, kev, min_epss, limit)


@router.get("/products/risk-ranking", response_model=list[ProductRiskRankingOut])
def products_risk_ranking(db: Session = Depends(get_db), limit: int = Query(10, ge=1, le=50)):
    return _product_risk_ranking(db, limit)


@router.get("/products/monthly-delta", response_model=list[ProductMonthlyDeltaOut])
def products_monthly_delta(
    db: Session = Depends(get_db),
    current_release: str | None = None,
    previous_release: str | None = None,
    limit: int = Query(10, ge=1, le=50),
):
    return _product_monthly_delta(db, current_release, previous_release, limit)


@router.get("/products/mappings", response_model=list[ProductMappingOut])
def products_mappings(db: Session = Depends(get_db), limit: int = Query(500, ge=1, le=5000), offset: int = Query(0, ge=0)):
    return db.scalars(select(ProductMapping).order_by(ProductMapping.raw_name).limit(limit).offset(offset)).all()


@router.get("/products", response_model=list[ProductOut])
def list_products(db: Session = Depends(get_db)):
    return db.scalars(select(Product).order_by(Product.name)).all()


@router.get("/products/{product_id}", response_model=ProductOut)
def get_product(product_id: str, db: Session = Depends(get_db)):
    product = db.scalar(select(Product).where(Product.product_id == product_id))
    if not product:
        raise HTTPException(404, "Product not found")
    return product


@router.get("/releases", response_model=list[ReleaseOut])
def list_releases(db: Session = Depends(get_db)):
    return db.scalars(select(Release).order_by(Release.release_name.desc())).all()


@router.get("/releases/{release_name}", response_model=ReleaseOut)
def get_release(release_name: str, db: Session = Depends(get_db)):
    release = db.scalar(select(Release).where(Release.release_name == release_name))
    if not release:
        raise HTTPException(404, "Release not found")
    return release


@router.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db)):
    latest_release_date = select(func.max(Release.release_date)).scalar_subquery()
    latest = db.scalar(
        select(Release.release_name)
        .where(Release.release_date == latest_release_date)
        .order_by(Release.release_name.desc())
        .limit(1)
    )

    release_counts = db.execute(
        select(func.coalesce(Release.release_name, "Unknown"), func.count(Cve.id))
        .select_from(Cve)
        .outerjoin(Release)
        .group_by(Release.release_name)
        .order_by(func.count(Cve.id).desc(), Release.release_name)
    ).all()

    total_cves = db.scalar(select(func.count(Cve.id))) or 0

    total_kev = (
        db.scalar(
            select(func.count(func.distinct(CveEnrichment.cve_id))).where(
                CveEnrichment.source == "kev",
                CveEnrichment.kev_known_exploited.is_(True),
            )
        )
        or 0
    )

    top_epss_rows = db.execute(
        select(
            Cve.cve_id,
            Cve.title,
            CveEnrichment.epss_score,
            CveEnrichment.epss_percentile,
        )
        .join(CveEnrichment)
        .where(
            CveEnrichment.source == "epss",
            CveEnrichment.epss_score.is_not(None),
        )
        .order_by(CveEnrichment.epss_score.desc())
        .limit(20)
    ).all()

    kev_rows = (
        db.execute(
            select(Cve)
            .join(CveEnrichment)
            .where(
                CveEnrichment.source == "kev",
                CveEnrichment.kev_known_exploited.is_(True),
            )
            .options(
                joinedload(Cve.product_links).joinedload(CveProduct.product),
                joinedload(Cve.enrichments),
            )
            .order_by(Cve.cve_id)
        )
        .scalars()
        .unique()
        .all()
    )

    cves = (
        db.scalars(
            select(Cve).options(
                joinedload(Cve.product_links),
                joinedload(Cve.enrichments),
            )
        )
        .unique()
        .all()
    )

    score_buckets = [
        {"label": "0.0-3.9", "count": 0},
        {"label": "4.0-6.9", "count": 0},
        {"label": "7.0-8.9", "count": 0},
        {"label": "9.0-10.0", "count": 0},
        {"label": "Unknown", "count": 0},
    ]

    immediate_action_count = 0
    high_priority_count = 0
    routine_count = 0
    cvss_scores: list[float] = []
    known_impact_cves: set[int] = set()
    severity_counts: dict[str, int] = {}
    impact_counts: dict[str, int] = {}

    for cve in cves:
        severity = cve.severity or "Unknown"
        impact = cve.impact or "Unknown"

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        impact_counts[impact] = impact_counts.get(impact, 0) + 1

        cvss_score = cve.cvss_score if cve.cvss_score is not None else cve.nvd_cvss_score
        epss_score = cve.epss_score

        if impact != "Unknown":
            known_impact_cves.add(cve.id)

        if cvss_score is None:
            score_buckets[4]["count"] += 1
        elif cvss_score >= 9:
            cvss_scores.append(cvss_score)
            score_buckets[3]["count"] += 1
        elif cvss_score >= 7:
            cvss_scores.append(cvss_score)
            score_buckets[2]["count"] += 1
        elif cvss_score >= 4:
            cvss_scores.append(cvss_score)
            score_buckets[1]["count"] += 1
        else:
            cvss_scores.append(cvss_score)
            score_buckets[0]["count"] += 1

        if (
            cve.kev_known_exploited
            or cve.exploited
            or (cvss_score is not None and cvss_score >= 9)
            or (epss_score is not None and epss_score >= 0.5)
        ):
            immediate_action_count += 1
        elif (
            cve.severity == "Critical"
            or (cvss_score is not None and cvss_score >= 7)
            or (epss_score is not None and epss_score >= 0.2)
        ):
            high_priority_count += 1
        else:
            routine_count += 1

    return {
        "total_cves": total_cves,
        "total_products": db.scalar(select(func.count(Product.id))) or 0,
        "latest_release": latest,
        "count_by_severity": severity_counts,
        "exploited_count": db.scalar(
            select(func.count(func.distinct(CveProduct.cve_id))).where(
                CveProduct.exploited.is_(True)
            )
        )
        or 0,
        "publicly_disclosed_count": db.scalar(
            select(func.count(func.distinct(CveProduct.cve_id))).where(
                CveProduct.publicly_disclosed.is_(True)
            )
        )
        or 0,
        "total_kev_vulnerabilities": total_kev,
        "average_epss_score": db.scalar(
            select(func.avg(CveEnrichment.epss_score)).where(
                CveEnrichment.source == "epss",
                CveEnrichment.epss_score.is_not(None),
            )
        ),
        "top_epss_cves": [
            {
                "cve_id": row.cve_id,
                "title": row.title,
                "epss_score": row.epss_score,
                "epss_percentile": row.epss_percentile,
            }
            for row in top_epss_rows
        ],
        "critical_cves": severity_counts.get("Critical", 0),
        "highest_epss_score": db.scalar(
            select(func.max(CveEnrichment.epss_score)).where(
                CveEnrichment.source == "epss"
            )
        ),
        "average_cvss_score": sum(cvss_scores) / len(cvss_scores) if cvss_scores else None,
        "epss_enriched_cves": db.scalar(
            select(func.count(func.distinct(CveEnrichment.cve_id))).where(
                CveEnrichment.source == "epss",
                CveEnrichment.epss_score.is_not(None),
            )
        )
        or 0,
        "epss_at_least_1_percent": db.scalar(
            select(func.count(func.distinct(CveEnrichment.cve_id))).where(
                CveEnrichment.source == "epss",
                CveEnrichment.epss_score >= 0.01,
            )
        )
        or 0,
        "epss_at_least_10_percent": db.scalar(
            select(func.count(func.distinct(CveEnrichment.cve_id))).where(
                CveEnrichment.source == "epss",
                CveEnrichment.epss_score >= 0.10,
            )
        )
        or 0,
        "nvd_enriched_cves": db.scalar(
            select(func.count(func.distinct(CveEnrichment.cve_id))).where(
                CveEnrichment.source == "nvd"
            )
        )
        or 0,
        "impact_known_cves": len(known_impact_cves),
        "cvss_at_least_9": sum(
            1
            for cve in cves
            if (
                cve.cvss_score if cve.cvss_score is not None else cve.nvd_cvss_score
            )
            is not None
            and (
                cve.cvss_score if cve.cvss_score is not None else cve.nvd_cvss_score
            )
            >= 9
        ),
        "immediate_action_count": immediate_action_count,
        "high_priority_count": high_priority_count,
        "routine_count": routine_count,
        "cves_by_severity": [
            {"label": label, "count": count}
            for label, count in sorted(
                severity_counts.items(), key=lambda item: item[1], reverse=True
            )
        ],
        "cves_by_release": [{"label": row[0], "count": row[1]} for row in release_counts],
        "cves_by_impact": [
            {"label": label, "count": count}
            for label, count in sorted(
                impact_counts.items(), key=lambda item: item[1], reverse=True
            )
        ],
        "kev_distribution": [
            {"label": "CISA KEV", "count": total_kev},
            {"label": "Non-KEV", "count": max(total_cves - total_kev, 0)},
        ],
        "cvss_score_distribution": score_buckets,
        "top_product_families": _product_rollup(db, [func.coalesce(CveProduct.product_family, "Unknown"), func.coalesce(CveProduct.product_category, "Unknown")], limit=10),
        "top_product_categories": _product_rollup(db, [func.coalesce(CveProduct.product_category, "Unknown")], limit=12),
        "kev_cves": [
            {
                "cve_id": cve.cve_id,
                "title": cve.title,
                "product": cve.kev_product
                or next((link.product.name for link in cve.product_links if link.product), None),
                "epss_score": cve.epss_score,
                "cvss_score": cve.cvss_score
                if cve.cvss_score is not None
                else cve.nvd_cvss_score,
                "severity": cve.severity,
                "required_action": cve.kev_required_action,
                "due_date": cve.kev_due_date,
            }
            for cve in kev_rows
        ],
    }


@router.get("/stats/timeseries", response_model=list[StatsTimeseriesPointOut])
def stats_timeseries(db: Session = Depends(get_db)):
    releases = (
        db.scalars(
            select(Release)
            .where(Release.cves.any())
            .options(
                joinedload(Release.cves).joinedload(Cve.product_links),
                joinedload(Release.cves).joinedload(Cve.enrichments),
            )
            .order_by(Release.release_date.desc(), Release.release_name.desc())
            .limit(12)
        )
        .unique()
        .all()
    )

    points = []
    for release in sorted(
        releases,
        key=lambda item: (item.release_date or datetime.min, item.release_name),
    ):
        cvss_scores: list[float] = []
        critical_cves = 0
        high_epss_count = 0
        kev_count = 0

        for cve in release.cves:
            if cve.severity == "Critical":
                critical_cves += 1

            epss_score = cve.epss_score
            if epss_score is not None and epss_score >= 0.10:
                high_epss_count += 1

            if cve.kev_known_exploited:
                kev_count += 1

            cvss_score = cve.cvss_score if cve.cvss_score is not None else cve.nvd_cvss_score
            if cvss_score is not None:
                cvss_scores.append(cvss_score)

        points.append(
            {
                "label": release.release_name,
                "release_date": release.release_date,
                "total_cves": len(release.cves),
                "critical_cves": critical_cves,
                "high_epss_count": high_epss_count,
                "kev_count": kev_count,
                "average_cvss_score": sum(cvss_scores) / len(cvss_scores) if cvss_scores else None,
            }
        )

    return points


@router.post("/admin/sync")
def trigger_sync(payload: SyncRequest):
    release = payload.release_name or payload.release
    return {
        "status": "accepted",
        "release_name": release,
        "message": "Run collector sync for the requested release.",
    }
