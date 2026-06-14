"""add cve enrichment

Revision ID: 0003_cve_enrichment
Revises: 0002_release_sync_metadata
Create Date: 2026-06-14
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_cve_enrichment"
down_revision = "0002_release_sync_metadata"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "cve_enrichment",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.Integer(), sa.ForeignKey("cves.id"), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("cvss_score", sa.Float()),
        sa.Column("cvss_vector", sa.Text()),
        sa.Column("severity", sa.String(64)),
        sa.Column("epss_score", sa.Float()),
        sa.Column("epss_percentile", sa.Float()),
        sa.Column("kev_known_exploited", sa.Boolean()),
        sa.Column("kev_due_date", sa.Date()),
        sa.Column("kev_vendor_project", sa.Text()),
        sa.Column("kev_product", sa.Text()),
        sa.Column("kev_required_action", sa.Text()),
        sa.Column("kev_notes", sa.Text()),
        sa.Column("raw_json", sa.Text()),
        sa.Column("fetched_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("cve_id", "source"),
    )
    op.create_index("ix_cve_enrichment_cve_id", "cve_enrichment", ["cve_id"])
    op.create_index("ix_cve_enrichment_source", "cve_enrichment", ["source"])


def downgrade():
    op.drop_table("cve_enrichment")
