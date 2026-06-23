"""add ai context verification fields

Revision ID: 0006_ai_context_verification_fields
Revises: 0005_cve_ai_context
Create Date: 2026-06-23
"""

from alembic import op
import sqlalchemy as sa


revision = "0006_ai_context_verification_fields"
down_revision = "0005_cve_ai_context"
branch_labels = None
depends_on = None


EMPTY_ARRAY = "[]"


def upgrade():
    op.add_column(
        "cve_ai_context",
        sa.Column("how_to_check", sa.JSON(), nullable=False, server_default=EMPTY_ARRAY),
    )
    op.add_column(
        "cve_ai_context",
        sa.Column("powershell_checks", sa.JSON(), nullable=False, server_default=EMPTY_ARRAY),
    )
    op.add_column(
        "cve_ai_context",
        sa.Column("verification_notes", sa.JSON(), nullable=False, server_default=EMPTY_ARRAY),
    )


def downgrade():
    op.drop_column("cve_ai_context", "verification_notes")
    op.drop_column("cve_ai_context", "powershell_checks")
    op.drop_column("cve_ai_context", "how_to_check")
