from datetime import date
from pydantic import BaseModel, ConfigDict
class ProductOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; name: str; family: str | None = None; vendor: str
class AffectedProductOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; product: ProductOut; fixed_build: str | None = None; kb_article: str | None = None; download_url: str | None = None
class RemediationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; remediation_type: str | None = None; description: str | None = None; url: str | None = None
class ReleaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; release_name: str; release_date: date | None = None; revision_date: date | None = None; document_title: str | None = None
class CveOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; cve_id: str; title: str | None = None; description: str | None = None; severity: str | None = None; cvss_score: float | None = None; impact: str | None = None; publicly_disclosed: bool; exploited: bool; release: ReleaseOut | None = None
class CveDetailOut(CveOut):
    affected_products: list[AffectedProductOut] = []
    remediations: list[RemediationOut] = []
class SyncRequest(BaseModel):
    release: str | None = None
