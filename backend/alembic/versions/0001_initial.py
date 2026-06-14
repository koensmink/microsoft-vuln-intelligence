"""initial normalized schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-13
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "releases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("release_name", sa.String(32), nullable=False),
        sa.Column("alias", sa.String(32)),
        sa.Column("release_date", sa.DateTime()),
        sa.Column("revision_date", sa.DateTime()),
        sa.Column("document_title", sa.Text()),
        sa.Column("severity", sa.String(64)),
        sa.Column("cvrf_url", sa.Text()),
        sa.Column("last_synced_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
    )
    op.create_index("ix_releases_release_name", "releases", ["release_name"], unique=True)

    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("product_id", sa.String(64), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("cpe", sa.Text()),
        sa.Column("family", sa.Text()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
    )
    op.create_index("ix_products_product_id", "products", ["product_id"], unique=True)
    op.create_index("ix_products_name", "products", ["name"])

    op.create_table(
        "sync_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("release_name", sa.String(32)),
        sa.Column("started_at", sa.DateTime()),
        sa.Column("finished_at", sa.DateTime()),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("records_processed", sa.Integer()),
        sa.Column("error_message", sa.Text()),
    )
    op.create_index("ix_sync_runs_release_name", "sync_runs", ["release_name"])

    op.create_table(
        "cves",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("title", sa.Text()),
        sa.Column("description", sa.Text()),
        sa.Column("release_date", sa.Date()),
        sa.Column("release_id", sa.Integer(), sa.ForeignKey("releases.id")),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
    )
    op.create_index("ix_cves_cve_id", "cves", ["cve_id"], unique=True)

    op.create_table(
        "cve_products",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.Integer(), sa.ForeignKey("cves.id"), nullable=False),
        sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id"), nullable=False),
        sa.Column("status", sa.String(64)),
        sa.Column("severity", sa.String(64)),
        sa.Column("impact", sa.Text()),
        sa.Column("cvss_base_score", sa.Float()),
        sa.Column("cvss_temporal_score", sa.Float()),
        sa.Column("cvss_vector", sa.Text()),
        sa.Column("exploited", sa.Boolean()),
        sa.Column("publicly_disclosed", sa.Boolean()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("cve_id", "product_id"),
    )
    op.create_index("ix_cve_products_cve_id", "cve_products", ["cve_id"])
    op.create_index("ix_cve_products_product_id", "cve_products", ["product_id"])
    op.create_index("ix_cve_products_severity", "cve_products", ["severity"])

    op.create_table(
        "remediations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.Integer(), sa.ForeignKey("cves.id"), nullable=False),
        sa.Column("product_id", sa.Integer(), sa.ForeignKey("products.id")),
        sa.Column("remediation_type", sa.String(128)),
        sa.Column("subtype", sa.String(128)),
        sa.Column("description", sa.Text()),
        sa.Column("url", sa.Text()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("cve_id", "product_id", "remediation_type", "description", "url"),
    )
    op.create_index("ix_remediations_cve_id", "remediations", ["cve_id"])
    op.create_index("ix_remediations_product_id", "remediations", ["product_id"])


def downgrade():
    op.drop_table("remediations")
    op.drop_table("cve_products")
    op.drop_table("cves")
    op.drop_table("sync_runs")
    op.drop_table("products")
    op.drop_table("releases")
