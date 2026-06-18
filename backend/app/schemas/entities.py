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


class CveEnrichmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source: str
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev_known_exploited: bool | None = None
    kev_due_date: date | None = None
    kev_vendor_project: str | None = None
    kev_product: str | None = None
    kev_required_action: str | None = None
    kev_notes: str | None = None
    fetched_at: datetime | None = None


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
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev_known_exploited: bool = False
    kev_due_date: date | None = None
    kev_vendor_project: str | None = None
    kev_product: str | None = None
    kev_required_action: str | None = None
    nvd_cvss_score: float | None = None
    nvd_cvss_vector: str | None = None


class CveDetailOut(CveOut):
    affected_products: list[CveProductOut] = []
    remediations: list[RemediationOut] = []
    enrichments: list[CveEnrichmentOut] = []


class TopEpssCveOut(BaseModel):
    cve_id: str
    title: str | None = None
    epss_score: float
    epss_percentile: float | None = None


class CountBucketOut(BaseModel):
    label: str
    count: int


class KevCveOut(BaseModel):
    cve_id: str
    title: str | None = None
    product: str | None = None
    epss_score: float | None = None
    cvss_score: float | None = None
    severity: str | None = None
    required_action: str | None = None
    due_date: date | None = None


class StatsOut(BaseModel):
    total_cves: int
    total_products: int
    latest_release: str | None
    count_by_severity: dict[str, int]
    exploited_count: int
    publicly_disclosed_count: int
    total_kev_vulnerabilities: int
    average_epss_score: float | None = None
    average_cvss_score: float | None = None
    top_epss_cves: list[TopEpssCveOut] = []
    critical_cves: int = 0
    highest_epss_score: float | None = None
    epss_enriched_cves: int = 0
    epss_at_least_1_percent: int = 0
    epss_at_least_10_percent: int = 0
    nvd_enriched_cves: int = 0
    impact_known_cves: int = 0
    cvss_at_least_9: int = 0
    immediate_action_count: int = 0
    high_priority_count: int = 0
    routine_count: int = 0
    cves_by_severity: list[CountBucketOut] = []
    cves_by_release: list[CountBucketOut] = []
    cves_by_impact: list[CountBucketOut] = []
    kev_distribution: list[CountBucketOut] = []
    cvss_score_distribution: list[CountBucketOut] = []
    kev_cves: list[KevCveOut] = []


class SyncRequest(BaseModel):
    release_name: str | None = None
    release: str | None = None
