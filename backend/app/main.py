import logging
from time import perf_counter
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.api.routes import router
from app.core.config import settings
from app.core.stats_cache import stats_cache
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.rate_limit_per_minute}/minute"])
app = FastAPI(title="Microsoft Vulnerability Intelligence API")
app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://microsoftpatchtuesday.nl",
        "https://www.microsoftpatchtuesday.nl",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SlowAPIMiddleware)


class StatsCacheMiddleware(BaseHTTPMiddleware):
    """Cache only explicitly approved, expensive, successful GET responses."""

    static_paths = {
        "/api/v1/stats",
        "/api/v1/stats/timeseries",
        "/api/v1/system/data-quality",
        "/api/v1/products/summary",
        "/api/v1/products/categories",
        "/api/v1/products/risk-ranking",
    }

    @classmethod
    def is_cacheable(cls, path: str) -> bool:
        if path in cls.static_paths:
            return True
        parts = path.removeprefix("/api/v1/releases/").split("/")
        return len(parts) == 2 and bool(parts[0]) and parts[1] == "summary"

    async def dispatch(self, request: Request, call_next):
        if (
            request.method != "GET"
            or settings.stats_cache_ttl_seconds == 0
            or not self.is_cacheable(request.url.path)
        ):
            return await call_next(request)

        query = "&".join(
            f"{key}={value}" for key, value in sorted(request.query_params.multi_items())
        )
        key = f"{request.url.path}?{query}"
        cached = stats_cache.get(key)
        if cached is not None:
            logging.getLogger("app.cache").debug("cache hit path=%s", request.url.path)
            return Response(
                content=cached.body,
                status_code=cached.status_code,
                headers=dict(cached.headers),
            )

        logging.getLogger("app.cache").debug("cache miss path=%s", request.url.path)
        response = await call_next(request)
        if 200 <= response.status_code < 300:
            body = b"".join([chunk async for chunk in response.body_iterator])
            headers = tuple(response.headers.items())
            stats_cache.set(
                key,
                body=body,
                status_code=response.status_code,
                headers=headers,
                ttl_seconds=settings.stats_cache_ttl_seconds,
            )
            return Response(content=body, status_code=response.status_code, headers=dict(headers))
        return response


class RequestTimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        started_at = perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            duration_ms = (perf_counter() - started_at) * 1000
            logging.getLogger("app.request").info(
                "request method=%s path=%s status=%s duration_ms=%.2f",
                request.method,
                request.url.path,
                status_code,
                duration_ms,
            )


app.add_middleware(StatsCacheMiddleware)
app.add_middleware(RequestTimingMiddleware)
@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
app.include_router(router)
