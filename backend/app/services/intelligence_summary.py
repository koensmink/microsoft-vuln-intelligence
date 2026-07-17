from __future__ import annotations

from datetime import datetime

from sqlalchemy import and_, case, func, literal, or_, select, union_all
from sqlalchemy.orm import Session

from app.models.entities import Cve, CveAiContext, CveEnrichment, CveProduct, Release, SyncRun


def calculate_priority(
    *,
    kev: bool,
    exploited: bool,
    publicly_disclosed: bool,
    severity: str | None,
    cvss_score: float | None,
    epss_score: float | None,
) -> tuple[int, str, list[str]]:
    score = 0
    reasons = []
    if kev:
        score += 40
        reasons.append("Present in CISA KEV")
    if exploited:
        score += 35
        reasons.append("Known exploitation reported")
    if publicly_disclosed:
        score += 10
        reasons.append("Publicly disclosed")
    if (severity or "").strip().lower() == "critical":
        score += 15
        reasons.append("Critical severity")
    if cvss_score is not None and cvss_score >= 9.0:
        score += 10
        reasons.append("CVSS score of 9.0 or higher")
    if epss_score is not None and epss_score >= 0.10:
        score += 20
        reasons.append("EPSS probability of 10% or higher")
    elif epss_score is not None and epss_score >= 0.01:
        score += 10
        reasons.append("EPSS probability of 1% or higher")

    score = min(score, 100)
    level = "immediate" if score >= 70 else "high" if score >= 40 else "routine"
    return score, level, reasons


def _severity_rank(column):
    return case(
        (func.lower(func.trim(column)) == "critical", 4),
        (func.lower(func.trim(column)) == "important", 3),
        (func.lower(func.trim(column)) == "moderate", 2),
        (func.lower(func.trim(column)) == "low", 1),
        else_=0,
    )


def _consolidated_cves():
    # Pick the product row with highest semantic severity, then CVSS, then names.
    # The final id tie-breaker also makes duplicate product labels deterministic.
    ranked_products = select(
        CveProduct.cve_id,
        CveProduct.product_family,
        CveProduct.product_category,
        CveProduct.severity,
        func.row_number().over(
            partition_by=CveProduct.cve_id,
            order_by=(
                _severity_rank(CveProduct.severity).desc(),
                CveProduct.cvss_base_score.desc().nullslast(),
                func.coalesce(CveProduct.product_family, "").asc(),
                func.coalesce(CveProduct.product_category, "").asc(),
                CveProduct.id.asc(),
            ),
        ).label("row_number"),
    ).subquery()
    representative = select(ranked_products).where(ranked_products.c.row_number == 1).subquery()

    product_rollup = select(
        CveProduct.cve_id,
        func.max(case((CveProduct.exploited.is_(True), 1), else_=0)).label("exploited"),
        func.max(case((CveProduct.publicly_disclosed.is_(True), 1), else_=0)).label("publicly_disclosed"),
    ).group_by(CveProduct.cve_id).subquery()
    enrichment_rollup = select(
        CveEnrichment.cve_id,
        func.max(CveEnrichment.epss_score).label("epss_score"),
        func.max(case((CveEnrichment.kev_known_exploited.is_(True), 1), else_=0)).label("kev"),
    ).group_by(CveEnrichment.cve_id).subquery()
    all_cvss = union_all(
        select(CveProduct.cve_id.label("cve_id"), CveProduct.cvss_base_score.label("score")).where(CveProduct.cvss_base_score.is_not(None)),
        select(CveEnrichment.cve_id.label("cve_id"), CveEnrichment.cvss_score.label("score")).where(CveEnrichment.cvss_score.is_not(None)),
    ).subquery()
    cvss_rollup = select(all_cvss.c.cve_id, func.max(all_cvss.c.score).label("cvss_score")).group_by(all_cvss.c.cve_id).subquery()

    severity = func.coalesce(representative.c.severity, "Unknown").label("severity")
    kev = func.coalesce(enrichment_rollup.c.kev, 0).label("kev")
    exploited = func.coalesce(product_rollup.c.exploited, 0).label("exploited")
    disclosed = func.coalesce(product_rollup.c.publicly_disclosed, 0).label("publicly_disclosed")
    epss_points = case(
        (enrichment_rollup.c.epss_score >= 0.10, 20),
        (enrichment_rollup.c.epss_score >= 0.01, 10),
        else_=0,
    )
    raw_score = (
        kev * 40 + exploited * 35 + disclosed * 10
        + case((func.lower(func.trim(severity)) == "critical", 15), else_=0)
        + case((cvss_rollup.c.cvss_score >= 9.0, 10), else_=0)
        + epss_points
    )
    priority_score = case((raw_score > 100, 100), else_=raw_score).label("priority_score")
    priority_level = case(
        (raw_score >= 70, literal("immediate")),
        (raw_score >= 40, literal("high")),
        else_=literal("routine"),
    ).label("priority_level")
    return select(
        Cve.id.label("cve_pk"), Cve.cve_id, Cve.title, Cve.release_id,
        representative.c.product_family, representative.c.product_category,
        severity, cvss_rollup.c.cvss_score, enrichment_rollup.c.epss_score,
        kev, exploited, disclosed, priority_score, priority_level,
    ).select_from(Cve).outerjoin(representative, representative.c.cve_id == Cve.id).outerjoin(
        product_rollup, product_rollup.c.cve_id == Cve.id
    ).outerjoin(enrichment_rollup, enrichment_rollup.c.cve_id == Cve.id).outerjoin(
        cvss_rollup, cvss_rollup.c.cve_id == Cve.id
    ).subquery()


def get_prioritized_cves(
    db: Session, *, release: str | None = None, priority: str | None = None,
    limit: int = 25, offset: int = 0, product_family: str | None = None,
    product_category: str | None = None,
) -> list[dict]:
    consolidated = _consolidated_cves()
    stmt = select(consolidated)
    if release is not None:
        stmt = stmt.join(Release, Release.id == consolidated.c.release_id).where(Release.release_name == release)
    if priority is not None:
        stmt = stmt.where(consolidated.c.priority_level == priority)
    if product_family is not None:
        stmt = stmt.where(func.lower(func.trim(consolidated.c.product_family)) == product_family.strip().lower())
    if product_category is not None:
        stmt = stmt.where(func.lower(func.trim(consolidated.c.product_category)) == product_category.strip().lower())
    stmt = stmt.order_by(
        consolidated.c.priority_score.desc(), consolidated.c.kev.desc(),
        consolidated.c.exploited.desc(), consolidated.c.epss_score.desc().nullslast(),
        consolidated.c.cvss_score.desc().nullslast(), consolidated.c.cve_id.desc(),
    ).limit(limit).offset(offset)

    results = []
    for row in db.execute(stmt).mappings():
        score, level, reasons = calculate_priority(
            kev=bool(row["kev"]), exploited=bool(row["exploited"]),
            publicly_disclosed=bool(row["publicly_disclosed"]), severity=row["severity"],
            cvss_score=row["cvss_score"], epss_score=row["epss_score"],
        )
        results.append({
            "cve_id": row["cve_id"], "title": row["title"],
            "product_family": row["product_family"], "product_category": row["product_category"],
            "severity": row["severity"], "cvss_score": row["cvss_score"],
            "epss_score": row["epss_score"], "kev": bool(row["kev"]),
            "exploited": bool(row["exploited"]), "publicly_disclosed": bool(row["publicly_disclosed"]),
            "priority_score": score, "priority_level": level, "priority_reasons": reasons,
        })
    return results


def _release_metrics(db: Session, release_id: int) -> dict:
    consolidated = _consolidated_cves()
    row = db.execute(select(
        func.count(consolidated.c.cve_pk).label("total_cves"),
        func.sum(case((func.lower(func.trim(consolidated.c.severity)) == "critical", 1), else_=0)).label("critical_cves"),
        func.sum(consolidated.c.exploited).label("exploited_cves"),
        func.sum(consolidated.c.publicly_disclosed).label("publicly_disclosed_cves"),
        func.sum(consolidated.c.kev).label("kev_cves"),
        func.sum(case((consolidated.c.epss_score >= 0.10, 1), else_=0)).label("high_epss_cves"),
        func.avg(consolidated.c.cvss_score).label("average_cvss_score"),
        func.max(consolidated.c.cvss_score).label("highest_cvss_score"),
        func.max(consolidated.c.epss_score).label("highest_epss_score"),
    ).where(consolidated.c.release_id == release_id)).mappings().one()
    families = db.scalar(select(func.count(func.distinct(func.trim(CveProduct.product_family)))).join(Cve).where(
        Cve.release_id == release_id, CveProduct.product_family.is_not(None), func.trim(CveProduct.product_family) != "",
    )) or 0
    return {
        "total_cves": row["total_cves"] or 0, "critical_cves": row["critical_cves"] or 0,
        "exploited_cves": row["exploited_cves"] or 0,
        "publicly_disclosed_cves": row["publicly_disclosed_cves"] or 0,
        "kev_cves": row["kev_cves"] or 0, "high_epss_cves": row["high_epss_cves"] or 0,
        "average_cvss_score": round(float(row["average_cvss_score"]), 2) if row["average_cvss_score"] is not None else None,
        "highest_cvss_score": row["highest_cvss_score"], "highest_epss_score": row["highest_epss_score"],
        "affected_product_families": families,
    }


def get_release_summary(db: Session, release_name: str) -> dict | None:
    release = db.scalar(select(Release).where(Release.release_name == release_name))
    if release is None:
        return None
    metrics = _release_metrics(db, release.id)
    previous = db.scalar(select(Release).where(
        Release.release_date.is_not(None), Release.release_date < release.release_date,
    ).order_by(Release.release_date.desc(), Release.release_name.desc()).limit(1)) if release.release_date is not None else None
    previous_metrics = _release_metrics(db, previous.id) if previous else None
    return {
        "release": release.release_name, "release_date": release.release_date, **metrics,
        "previous_release": previous.release_name if previous else None,
        "cve_delta": metrics["total_cves"] - previous_metrics["total_cves"] if previous_metrics else None,
        "critical_delta": metrics["critical_cves"] - previous_metrics["critical_cves"] if previous_metrics else None,
        "priority_cves": get_prioritized_cves(db, release=release.release_name, limit=10),
    }


def get_system_status(db: Session, *, now: datetime | None = None) -> dict:
    now = now or datetime.utcnow()
    latest_release = db.scalar(select(Release).order_by(Release.release_date.desc().nullslast(), Release.release_name.desc()).limit(1))
    latest_sync = db.scalar(select(SyncRun).order_by(SyncRun.started_at.desc(), SyncRun.id.desc()).limit(1))
    successful_statuses = ("success", "completed")
    successful_sync = db.scalar(select(SyncRun).where(func.lower(SyncRun.status).in_(successful_statuses)).order_by(SyncRun.finished_at.desc().nullslast(), SyncRun.started_at.desc(), SyncRun.id.desc()).limit(1))
    successful_at = successful_sync.finished_at if successful_sync else None
    freshness_values = [value for value in (successful_at, latest_release.last_synced_at if latest_release else None) if value is not None]
    freshness = max(freshness_values) if freshness_values else None
    freshness_hours = round((now - freshness).total_seconds() / 3600, 2) if freshness else None
    latest_failed = latest_sync is not None and latest_sync.status.lower() not in successful_statuses
    healthy = latest_release is not None and freshness_hours is not None and freshness_hours <= 48 and not latest_failed
    return {
        "status": "healthy" if healthy else "degraded", "database": "healthy",
        "latest_release": latest_release.release_name if latest_release else None,
        "latest_release_date": latest_release.release_date if latest_release else None,
        "last_successful_sync": successful_at, "last_sync_status": latest_sync.status if latest_sync else None,
        "records_processed": latest_sync.records_processed if latest_sync else None,
        "data_freshness_hours": freshness_hours,
    }


def _coverage(total: int, covered: int) -> dict:
    return {"covered": covered, "missing": total - covered, "percentage": round(covered / total * 100, 2) if total else 0.0}


def get_data_quality(db: Session) -> dict:
    total = db.scalar(select(func.count(Cve.id))) or 0
    epss = db.scalar(select(func.count(func.distinct(CveEnrichment.cve_id))).where(CveEnrichment.epss_score.is_not(None))) or 0
    nvd = db.scalar(select(func.count(func.distinct(CveEnrichment.cve_id))).where(
        func.lower(CveEnrichment.source) == "nvd",
        or_(CveEnrichment.cvss_score.is_not(None), and_(CveEnrichment.cvss_vector.is_not(None), func.trim(CveEnrichment.cvss_vector) != "")),
    )) or 0
    ai = db.scalar(select(func.count(func.distinct(CveAiContext.cve_id)))) or 0
    products = db.scalar(select(func.count(func.distinct(CveProduct.cve_id))).where(
        CveProduct.product_family.is_not(None), func.trim(CveProduct.product_family) != "",
        func.lower(func.trim(CveProduct.product_family)) != "other microsoft product",
        CveProduct.product_category.is_not(None), func.trim(CveProduct.product_category) != "",
        func.lower(func.trim(CveProduct.product_category)) != "unknown",
    )) or 0
    return {
        "total_cves": total, "epss_coverage": _coverage(total, epss), "nvd_coverage": _coverage(total, nvd),
        "ai_context_coverage": _coverage(total, ai), "product_classification": _coverage(total, products),
    }
