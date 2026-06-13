from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import extract, select
from sqlalchemy.orm import Session, joinedload
from app.db.session import get_db
from app.models import AffectedProduct, Cve, Product, Release
from app.schemas import CveDetailOut, CveOut, ProductOut, ReleaseOut, SyncRequest
router = APIRouter(prefix="/api/v1")
@router.get("/health")
def health(): return {"status": "ok"}
@router.get("/cves", response_model=list[CveOut])
def list_cves(db: Session = Depends(get_db), severity: str | None = None, product: str | None = None, year: int | None = None, month: int | None = None, exploited: bool | None = None, publicly_disclosed: bool | None = None):
    stmt = select(Cve).options(joinedload(Cve.release))
    if severity: stmt = stmt.where(Cve.severity == severity)
    if exploited is not None: stmt = stmt.where(Cve.exploited == exploited)
    if publicly_disclosed is not None: stmt = stmt.where(Cve.publicly_disclosed == publicly_disclosed)
    if year: stmt = stmt.join(Cve.release).where(extract("year", Release.release_date) == year)
    if month: stmt = stmt.join(Cve.release).where(extract("month", Release.release_date) == month)
    if product: stmt = stmt.join(Cve.affected_products).join(Product).where(Product.name.ilike(f"%{product}%"))
    return db.scalars(stmt).unique().all()
@router.get("/cves/{cve_id}", response_model=CveDetailOut)
def get_cve(cve_id: str, db: Session = Depends(get_db)):
    cve = db.scalar(select(Cve).where(Cve.cve_id == cve_id).options(joinedload(Cve.release), joinedload(Cve.affected_products).joinedload(AffectedProduct.product), joinedload(Cve.remediations)))
    if not cve: raise HTTPException(404, "CVE not found")
    return cve
@router.get("/products", response_model=list[ProductOut])
def list_products(db: Session = Depends(get_db)): return db.scalars(select(Product).order_by(Product.name)).all()
@router.get("/products/{id}", response_model=ProductOut)
def get_product(id: int, db: Session = Depends(get_db)):
    product = db.get(Product, id)
    if not product: raise HTTPException(404, "Product not found")
    return product
@router.get("/releases", response_model=list[ReleaseOut])
def list_releases(db: Session = Depends(get_db)): return db.scalars(select(Release).order_by(Release.release_name.desc())).all()
@router.get("/releases/{release_name}", response_model=ReleaseOut)
def get_release(release_name: str, db: Session = Depends(get_db)):
    release = db.scalar(select(Release).where(Release.release_name == release_name))
    if not release: raise HTTPException(404, "Release not found")
    return release
@router.post("/admin/sync")
def trigger_sync(payload: SyncRequest):
    return {"status": "accepted", "release": payload.release, "message": "Run `python sync.py` in collector for full import."}
