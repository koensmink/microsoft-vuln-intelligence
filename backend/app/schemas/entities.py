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
    product_family: str | None = None
    product_category: str | None = None


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


class PowerShellCheckOut(BaseModel):
    title: str
    command: str
    explanation: str
    applies_to: str


class AiContextBatchFailureOut(BaseModel):
    cve_id: str
    error: str


class AiContextBatchGenerateOut(BaseModel):
    selected: int
    generated: int
    skipped: int
    failed: int
    failures: list[AiContextBatchFailureOut] = []


class CveAiContextOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cve_id: int
    language: str = "nl"
    model: str
    plain_summary: str
    business_impact: str
    who_should_act: list[str]
    what_to_check: list[str]
    recommended_action: str
    technical_context: str
    confidence: str
    limitations: list[str]
    how_to_check: list[str] = []
    powershell_checks: list[PowerShellCheckOut] = []
    verification_notes: list[str] = []
    source_hash: str
    created_at: datetime | None = None
    updated_at: datetime | None = None


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


class StatsTimeseriesPointOut(BaseModel):
    label: str
    release_date: date | datetime | None = None
    total_cves: int
    critical_cves: int
    high_epss_count: int
    kev_count: int
    average_cvss_score: float | None = None


class ProductSummaryOut(BaseModel):
    product_family: str
    product_category: str
    cve_count: int
    critical_count: int = 0
    kev_count: int = 0
    high_epss_count: int = 0
    average_cvss_score: float | None = None


class ProductCategoryOut(BaseModel):
    product_category: str
    cve_count: int
    critical_count: int = 0
    kev_count: int = 0
    high_epss_count: int = 0
    average_cvss_score: float | None = None


class ProductMonthlyDeltaOut(BaseModel):
    product_family: str
    product_category: str
    current_release: str
    previous_release: str
    current_cve_count: int
    previous_cve_count: int
    delta_cve_count: int
    current_critical_count: int
    previous_critical_count: int
    delta_critical_count: int
    current_kev_count: int
    previous_kev_count: int
    delta_kev_count: int
    current_high_epss_count: int
    previous_high_epss_count: int
    delta_high_epss_count: int
    delta_priority_score: int


class ProductRiskRankingOut(ProductSummaryOut):
    average_cvss_score: float = 0
    risk_score: float
    risk_level: str


class ProductMappingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    raw_name: str
    product_family: str | None = None
    product_category: str | None = None
    confidence: float | None = None
    source: str = "rule"
    created_at: datetime | None = None
    updated_at: datetime | None = None


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
    top_product_families: list[ProductSummaryOut] = []
    top_product_categories: list[ProductCategoryOut] = []


class SyncRequest(BaseModel):
    release_name: str | None = None
    release: str | None = None
