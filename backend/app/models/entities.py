from datetime import datetime

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Release(Base):
    __tablename__ = "releases"

    id: Mapped[int] = mapped_column(primary_key=True)
    release_name: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    release_date: Mapped[datetime | None] = mapped_column(Date, nullable=True)
    revision_date: Mapped[datetime | None] = mapped_column(Date, nullable=True)
    document_title: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    cves: Mapped[list["Cve"]] = relationship(back_populates="release")


class Cve(Base):
    __tablename__ = "cves"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    release_date: Mapped[datetime | None] = mapped_column(Date, nullable=True)
    release_id: Mapped[int | None] = mapped_column(ForeignKey("releases.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    release: Mapped[Release | None] = relationship(back_populates="cves")
    product_links: Mapped[list["CveProduct"]] = relationship(back_populates="cve", cascade="all, delete-orphan")
    remediations: Mapped[list["Remediation"]] = relationship(back_populates="cve", cascade="all, delete-orphan")

    @property
    def affected_products(self) -> list["CveProduct"]:
        return self.product_links

    @property
    def severity(self) -> str | None:
        severities = [link.severity for link in self.product_links if link.severity]
        order = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}
        return max(severities, key=lambda item: order.get(item, 0), default=None)

    @property
    def impact(self) -> str | None:
        return next((link.impact for link in self.product_links if link.impact), None)

    @property
    def cvss_score(self) -> float | None:
        scores = [link.cvss_base_score for link in self.product_links if link.cvss_base_score is not None]
        return max(scores, default=None)

    @property
    def exploited(self) -> bool:
        return any(link.exploited for link in self.product_links)

    @property
    def publicly_disclosed(self) -> bool:
        return any(link.publicly_disclosed for link in self.product_links)

    @property
    def affected_product_count(self) -> int:
        return len(self.product_links)


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(Text, index=True)
    cpe: Mapped[str | None] = mapped_column(Text)
    family: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    cve_links: Mapped[list["CveProduct"]] = relationship(back_populates="product")

    @property
    def cve_count(self) -> int:
        return len(self.cve_links)


class CveProduct(Base):
    __tablename__ = "cve_products"
    __table_args__ = (UniqueConstraint("cve_id", "product_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id"), index=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), index=True)
    status: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str | None] = mapped_column(String(64), index=True)
    impact: Mapped[str | None] = mapped_column(Text)
    cvss_base_score: Mapped[float | None] = mapped_column(Float)
    cvss_temporal_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    exploited: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    publicly_disclosed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    cve: Mapped[Cve] = relationship(back_populates="product_links")
    product: Mapped[Product] = relationship(back_populates="cve_links")


AffectedProduct = CveProduct


class Remediation(Base):
    __tablename__ = "remediations"
    __table_args__ = (UniqueConstraint("cve_id", "product_id", "remediation_type", "description", "url"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id"), index=True)
    product_id: Mapped[int | None] = mapped_column(ForeignKey("products.id"), index=True)
    remediation_type: Mapped[str | None] = mapped_column(String(128))
    subtype: Mapped[str | None] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    cve: Mapped[Cve] = relationship(back_populates="remediations")
    product: Mapped[Product | None] = relationship()


class SyncRun(Base):
    __tablename__ = "sync_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    release_name: Mapped[str | None] = mapped_column(String(32), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(64))
    records_processed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
