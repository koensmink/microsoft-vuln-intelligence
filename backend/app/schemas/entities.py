from datetime import date, datetime
from pydantic import BaseModel, ConfigDict


class ProductOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    product_id: str
    name: str
    cpe: str | None = None
    family: str | None = None
    cve_count: int | None = None


class CveProductOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    product: ProductOut
    status: str | None = None
    severity: str | None = None
    impact: str | None = None
    cvss_base_score: float | None = None
    cvss_temporal_score: float | None = None
    cvss_vector: str | None = None
    exploited: bool
    publicly_disclosed: bool


AffectedProductOut = CveProductOut


class RemediationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    product: ProductOut | None = None
    remediation_type: str | None = None
    subtype: str | None = None
    description: str | None = None
    url: str | None = None


class ReleaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    release_name: str
    alias: str | None = None
    release_date: date | datetime | None = None
    revision_date: date | datetime | None = None
    document_title: str | None = None
    severity: str | None = None
    cvrf_url: str | None = None
    last_synced_at: datetime | None = None


class CveOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cve_id: str
    title: str | None = None
    description: str | None = None
    release_date: date | None = None
    severity: str | None = None
    cvss_score: float | None = None
    impact: str | None = None
    publicly_disclosed: bool
    exploited: bool
    release: ReleaseOut | None = None
    affected_product_count: int | None = None


class CveDetailOut(CveOut):
    affected_products: list[CveProductOut] = []
    remediations: list[RemediationOut] = []


class StatsOut(BaseModel):
    total_cves: int
    total_products: int
    latest_release: str | None
    count_by_severity: dict[str, int]
    exploited_count: int
    publicly_disclosed_count: int


class SyncRequest(BaseModel):
    release_name: str | None = None
    release: str | None = None
