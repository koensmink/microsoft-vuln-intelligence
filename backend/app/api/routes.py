from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models import AffectedProduct, Cve, Product, Release
from app.models.entities import CveEnrichment, CveProduct
from app.schemas import (
    CveDetailOut,
    CveEnrichmentOut,
    CveOut,
    ProductOut,
    ReleaseOut,
    StatsOut,
    StatsTimeseriesPointOut,
    SyncRequest,
)

router = APIRouter(prefix="/api/v1")


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
