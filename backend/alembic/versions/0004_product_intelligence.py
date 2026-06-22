"""add product intelligence

Revision ID: 0004_product_intelligence
Revises: 0003_cve_enrichment
Create Date: 2026-06-22
"""

from alembic import op
import sqlalchemy as sa


revision = "0004_product_intelligence"
down_revision = "0003_cve_enrichment"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "product_mappings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("raw_name", sa.Text(), nullable=False),
        sa.Column("product_family", sa.Text(), nullable=True),
        sa.Column("product_category", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("source", sa.String(64), nullable=False, server_default="rule"),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
        sa.UniqueConstraint("raw_name"),
    )
    op.create_index("ix_product_mappings_raw_name", "product_mappings", ["raw_name"])
    op.add_column("cve_products", sa.Column("product_family", sa.Text(), nullable=True))
    op.add_column("cve_products", sa.Column("product_category", sa.Text(), nullable=True))
    op.create_index("ix_cve_products_product_family", "cve_products", ["product_family"])
    op.create_index("ix_cve_products_product_category", "cve_products", ["product_category"])


def downgrade():
    op.drop_index("ix_cve_products_product_category", table_name="cve_products")
    op.drop_index("ix_cve_products_product_family", table_name="cve_products")
    op.drop_column("cve_products", "product_category")
    op.drop_column("cve_products", "product_family")
    op.drop_index("ix_product_mappings_raw_name", table_name="product_mappings")
    op.drop_table("product_mappings")
