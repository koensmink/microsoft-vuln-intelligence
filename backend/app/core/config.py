from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    database_url: str = "sqlite+pysqlite:///./dev.db"
    msrc_api_base_url: str = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"
    rate_limit_per_minute: int = 120
    openai_api_key: str | None = None
    ai_admin_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
settings = Settings()
