import pytest

from app.core.stats_cache import stats_cache


@pytest.fixture(autouse=True)
def clear_stats_cache():
    stats_cache.clear()
    yield
    stats_cache.clear()
