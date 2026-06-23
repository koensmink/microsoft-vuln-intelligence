"""add cve ai context

Revision ID: 0005_cve_ai_context
Revises: 0004_product_intelligence
Create Date: 2026-06-23
"""

from alembic import op
import sqlalchemy as sa


revision = "0005_cve_ai_context"
down_revision = "0004_product_intelligence"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "cve_ai_context",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.Integer(), sa.ForeignKey("cves.id"), nullable=False),
        sa.Column("language", sa.String(8), nullable=False, server_default="nl"),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("plain_summary", sa.Text(), nullable=False),
        sa.Column("business_impact", sa.Text(), nullable=False),
        sa.Column("who_should_act", sa.JSON(), nullable=False),
        sa.Column("what_to_check", sa.JSON(), nullable=False),
        sa.Column("recommended_action", sa.Text(), nullable=False),
        sa.Column("technical_context", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(64), nullable=False),
        sa.Column("limitations", sa.JSON(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("cve_id", "language"),
    )
    op.create_index("ix_cve_ai_context_cve_id", "cve_ai_context", ["cve_id"])
    op.create_index("ix_cve_ai_context_language", "cve_ai_context", ["language"])
    op.create_index("ix_cve_ai_context_source_hash", "cve_ai_context", ["source_hash"])


def downgrade():
    op.drop_index("ix_cve_ai_context_source_hash", table_name="cve_ai_context")
    op.drop_index("ix_cve_ai_context_language", table_name="cve_ai_context")
    op.drop_index("ix_cve_ai_context_cve_id", table_name="cve_ai_context")
    op.drop_table("cve_ai_context")
