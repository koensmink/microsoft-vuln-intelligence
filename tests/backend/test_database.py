from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.models import Cve, Product, Release


def test_database_relationships_are_normalized():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        release = Release(release_name='2026-Jun')
        product = Product(name='Windows Server', vendor='Microsoft')
        cve = Cve(cve_id='CVE-2026-12345', severity='Critical', exploited=False, publicly_disclosed=True, release=release)
        session.add_all([release, product, cve])
        session.commit()
        assert session.query(Cve).filter_by(cve_id='CVE-2026-12345').one().release.release_name == '2026-Jun'
