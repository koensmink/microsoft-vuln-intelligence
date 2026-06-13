"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-13
"""
from alembic import op
import sqlalchemy as sa
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None
def upgrade():
    op.create_table('releases', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('release_name', sa.String(32), nullable=False), sa.Column('release_date', sa.Date()), sa.Column('revision_date', sa.Date()), sa.Column('document_title', sa.String(255)), sa.Column('created_at', sa.DateTime()))
    op.create_index('ix_releases_release_name', 'releases', ['release_name'], unique=True)
    op.create_table('products', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('name', sa.String(255), nullable=False), sa.Column('family', sa.String(255)), sa.Column('vendor', sa.String(255), nullable=False))
    op.create_index('ix_products_name', 'products', ['name'], unique=True)
    op.create_table('sync_runs', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('started_at', sa.DateTime()), sa.Column('finished_at', sa.DateTime()), sa.Column('status', sa.String(64), nullable=False), sa.Column('records_processed', sa.Integer()), sa.Column('error_message', sa.Text()))
    op.create_table('cves', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('cve_id', sa.String(32), nullable=False), sa.Column('title', sa.String(255)), sa.Column('description', sa.Text()), sa.Column('severity', sa.String(64)), sa.Column('cvss_score', sa.Float()), sa.Column('impact', sa.String(255)), sa.Column('publicly_disclosed', sa.Boolean(), nullable=False), sa.Column('exploited', sa.Boolean(), nullable=False), sa.Column('release_id', sa.Integer(), sa.ForeignKey('releases.id')), sa.Column('created_at', sa.DateTime()), sa.Column('updated_at', sa.DateTime()))
    op.create_index('ix_cves_cve_id', 'cves', ['cve_id'], unique=True)
    op.create_index('ix_cves_severity', 'cves', ['severity'])
    op.create_index('ix_cves_exploited', 'cves', ['exploited'])
    op.create_index('ix_cves_publicly_disclosed', 'cves', ['publicly_disclosed'])
    op.create_table('affected_products', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('cve_id', sa.Integer(), sa.ForeignKey('cves.id'), nullable=False), sa.Column('product_id', sa.Integer(), sa.ForeignKey('products.id'), nullable=False), sa.Column('fixed_build', sa.String(128)), sa.Column('kb_article', sa.String(128)), sa.Column('download_url', sa.Text()), sa.UniqueConstraint('cve_id', 'product_id', 'fixed_build', 'kb_article'))
    op.create_index('ix_affected_products_cve_id', 'affected_products', ['cve_id'])
    op.create_index('ix_affected_products_product_id', 'affected_products', ['product_id'])
    op.create_table('remediations', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('cve_id', sa.Integer(), sa.ForeignKey('cves.id'), nullable=False), sa.Column('remediation_type', sa.String(128)), sa.Column('description', sa.Text()), sa.Column('url', sa.Text()), sa.UniqueConstraint('cve_id', 'remediation_type', 'url'))
    op.create_index('ix_remediations_cve_id', 'remediations', ['cve_id'])
def downgrade():
    op.drop_table('remediations'); op.drop_table('affected_products'); op.drop_table('cves'); op.drop_table('sync_runs'); op.drop_table('products'); op.drop_table('releases')
