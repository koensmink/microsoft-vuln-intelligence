"""add release sync metadata

Revision ID: 0002_release_sync_metadata
Revises: 0001_initial
Create Date: 2026-06-14
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_release_sync_metadata"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("releases", sa.Column("alias", sa.String(32)))
    op.alter_column("releases", "release_date", type_=sa.DateTime())
    op.alter_column("releases", "revision_date", type_=sa.DateTime())
    op.add_column("releases", sa.Column("severity", sa.String(64)))
    op.add_column("releases", sa.Column("cvrf_url", sa.Text()))
    op.add_column("releases", sa.Column("last_synced_at", sa.DateTime()))


def downgrade():
    op.drop_column("releases", "last_synced_at")
    op.drop_column("releases", "cvrf_url")
    op.drop_column("releases", "severity")
    op.alter_column("releases", "revision_date", type_=sa.Date())
    op.alter_column("releases", "release_date", type_=sa.Date())
    op.drop_column("releases", "alias")
