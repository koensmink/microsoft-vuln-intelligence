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
    document_title: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    cves: Mapped[list["Cve"]] = relationship(back_populates="release")
class Cve(Base):
    __tablename__ = "cves"
    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(64), index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    impact: Mapped[str | None] = mapped_column(String(255))
    publicly_disclosed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    exploited: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    release_id: Mapped[int | None] = mapped_column(ForeignKey("releases.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    release: Mapped[Release | None] = relationship(back_populates="cves")
    affected_products: Mapped[list["AffectedProduct"]] = relationship(back_populates="cve", cascade="all, delete-orphan")
    remediations: Mapped[list["Remediation"]] = relationship(back_populates="cve", cascade="all, delete-orphan")
class Product(Base):
    __tablename__ = "products"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    family: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str] = mapped_column(String(255), default="Microsoft")
class AffectedProduct(Base):
    __tablename__ = "affected_products"
    __table_args__ = (UniqueConstraint("cve_id", "product_id", "fixed_build", "kb_article"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id"), index=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), index=True)
    fixed_build: Mapped[str | None] = mapped_column(String(128))
    kb_article: Mapped[str | None] = mapped_column(String(128))
    download_url: Mapped[str | None] = mapped_column(Text)
    cve: Mapped[Cve] = relationship(back_populates="affected_products")
    product: Mapped[Product] = relationship()
class Remediation(Base):
    __tablename__ = "remediations"
    __table_args__ = (UniqueConstraint("cve_id", "remediation_type", "url"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id"), index=True)
    remediation_type: Mapped[str | None] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    cve: Mapped[Cve] = relationship(back_populates="remediations")
class SyncRun(Base):
    __tablename__ = "sync_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(64))
    records_processed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
