from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite+pysqlite:///./dev.db"
    msrc_api_base_url: str = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"
    rate_limit_per_minute: int = 120
    openai_api_key: str | None = None
    ai_admin_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    ai_batch_concurrency: int = Field(default=3, ge=1, le=5)
    stats_cache_ttl_seconds: int = Field(default=300, ge=0)


settings = Settings()
