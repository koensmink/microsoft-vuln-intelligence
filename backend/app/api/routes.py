from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models import AffectedProduct, Cve, Product, Release
from app.models.entities import CveEnrichment, CveProduct
from app.schemas import CveDetailOut, CveEnrichmentOut, CveOut, ProductOut, ReleaseOut, StatsOut, SyncRequest

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
):
    stmt = select(Cve).options(
        joinedload(Cve.release),
        joinedload(Cve.product_links).joinedload(CveProduct.product),
        joinedload(Cve.enrichments),
    )
    if search:
        stmt = stmt.outerjoin(Cve.product_links).outerjoin(Product).where(
            or_(Cve.cve_id.ilike(f"%{search}%"), Cve.title.ilike(f"%{search}%"), Product.name.ilike(f"%{search}%"))
        )
    if severity:
        stmt = stmt.join(Cve.product_links).where(CveProduct.severity == severity)
    if product:
        stmt = stmt.join(Cve.product_links).join(Product).where(or_(Product.name.ilike(f"%{product}%"), Product.product_id == product))
    if exploited is not None:
        stmt = stmt.join(Cve.product_links).where(CveProduct.exploited == exploited)
    if publicly_disclosed is not None:
        stmt = stmt.join(Cve.product_links).where(CveProduct.publicly_disclosed == publicly_disclosed)
    if release_name:
        stmt = stmt.join(Cve.release).where(Release.release_name == release_name)
    if kev_only:
        stmt = stmt.where(
            Cve.enrichments.any(
                (CveEnrichment.source == "kev") & (CveEnrichment.kev_known_exploited.is_(True))
            )
        )
    if min_epss_score is not None:
        stmt = stmt.where(
            Cve.enrichments.any(
                (CveEnrichment.source == "epss") & (CveEnrichment.epss_score >= min_epss_score)
            )
        )
    if min_cvss_score is not None:
        stmt = stmt.where(
            Cve.enrichments.any(
                (CveEnrichment.source == "nvd") & (CveEnrichment.cvss_score >= min_cvss_score)
            )
        )
    return db.scalars(stmt.order_by(Cve.cve_id).limit(limit).offset(offset)).unique().all()


@router.get("/enrichment/{cve_id}", response_model=list[CveEnrichmentOut])
def get_enrichment(cve_id: str, db: Session = Depends(get_db)):
    cve = db.scalar(select(Cve).where(Cve.cve_id == cve_id).options(joinedload(Cve.enrichments)))
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
    latest = db.scalar(select(Release.release_name).order_by(Release.release_name.desc()).limit(1))
    counts = dict(db.execute(select(CveProduct.severity, func.count()).group_by(CveProduct.severity)).all())
    top_epss_rows = db.execute(
        select(Cve.cve_id, Cve.title, CveEnrichment.epss_score, CveEnrichment.epss_percentile)
        .join(CveEnrichment)
        .where(CveEnrichment.source == "epss", CveEnrichment.epss_score.is_not(None))
        .order_by(CveEnrichment.epss_score.desc())
        .limit(10)
    ).all()
    return {
        "total_cves": db.scalar(select(func.count(Cve.id))) or 0,
        "total_products": db.scalar(select(func.count(Product.id))) or 0,
        "latest_release": latest,
        "count_by_severity": {str(k): v for k, v in counts.items() if k},
        "exploited_count": db.scalar(select(func.count(func.distinct(CveProduct.cve_id))).where(CveProduct.exploited.is_(True))) or 0,
        "publicly_disclosed_count": db.scalar(select(func.count(func.distinct(CveProduct.cve_id))).where(CveProduct.publicly_disclosed.is_(True))) or 0,
        "total_kev_vulnerabilities": db.scalar(
            select(func.count(func.distinct(CveEnrichment.cve_id))).where(
                CveEnrichment.source == "kev", CveEnrichment.kev_known_exploited.is_(True)
            )
        ) or 0,
        "average_epss_score": db.scalar(
            select(func.avg(CveEnrichment.epss_score)).where(
                CveEnrichment.source == "epss", CveEnrichment.epss_score.is_not(None)
            )
        ),
        "top_epss_cves": [
            {"cve_id": row.cve_id, "title": row.title, "epss_score": row.epss_score, "epss_percentile": row.epss_percentile}
            for row in top_epss_rows
        ],
    }


@router.post("/admin/sync")
def trigger_sync(payload: SyncRequest):
    release = payload.release_name or payload.release
    return {"status": "accepted", "release_name": release, "message": "Run collector sync for the requested release."}
