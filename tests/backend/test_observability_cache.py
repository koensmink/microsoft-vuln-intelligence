import logging

from fastapi import Request
from fastapi.testclient import TestClient

from app.core.stats_cache import stats_cache
from backend.app.main import app


def setup_function() -> None:
    stats_cache.clear()


def teardown_function() -> None:
    stats_cache.clear()


def test_request_timing_logs_method_path_status_and_duration_without_query(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="app.request"):
        response = TestClient(app).get("/api/v1/health?token=do-not-log")

    assert response.status_code == 200
    record = next(record for record in caplog.records if record.name == "app.request")
    assert "method=GET" in record.message
    assert "path=/api/v1/health" in record.message
    assert "status=200" in record.message
    assert "duration_ms=" in record.message
    assert "token" not in record.message
    assert "do-not-log" not in record.message


def test_stats_cache_records_miss_then_hit(monkeypatch, caplog) -> None:
    import backend.app.main as main

    calls = 0

    async def response(_request: Request):
        nonlocal calls
        calls += 1
        from starlette.responses import JSONResponse
        return JSONResponse({"calls": calls})

    monkeypatch.setattr(main.StatsCacheMiddleware, "is_cacheable", classmethod(lambda cls, path: path == "/cached"))
    test_app = main.FastAPI()
    test_app.add_middleware(main.StatsCacheMiddleware)
    test_app.get("/cached")(response)

    with caplog.at_level(logging.DEBUG, logger="app.cache"):
        client = TestClient(test_app)
        first = client.get("/cached", params={"limit": "10", "release": "Jul"})
        second = client.get("/cached", params={"release": "Jul", "limit": "10"})
        different = client.get("/cached", params={"release": "Aug", "limit": "10"})

    assert first.json() == {"calls": 1}
    assert second.json() == {"calls": 1}
    assert different.json() == {"calls": 2}
    assert calls == 2
    messages = [record.message for record in caplog.records if record.name == "app.cache"]
    assert sum("cache miss" in message for message in messages) == 2
    assert sum("cache hit" in message for message in messages) == 1


def test_stats_cache_does_not_cache_errors(monkeypatch) -> None:
    import backend.app.main as main
    from starlette.responses import JSONResponse

    calls = 0

    async def failing(_request: Request):
        nonlocal calls
        calls += 1
        return JSONResponse({"calls": calls}, status_code=503)

    monkeypatch.setattr(main.StatsCacheMiddleware, "is_cacheable", classmethod(lambda cls, path: path == "/cached"))
    test_app = main.FastAPI()
    test_app.add_middleware(main.StatsCacheMiddleware)
    test_app.get("/cached")(failing)
    client = TestClient(test_app)

    assert client.get("/cached").status_code == 503
    assert client.get("/cached").json() == {"calls": 2}
