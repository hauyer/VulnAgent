"""Environment-backed application settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings; real provider credentials are always optional in V0.2."""

    app_name: str = "VulnAgent"
    app_env: str = "development"
    log_level: str = "INFO"
    llm_provider: str = "mock"
    deepseek_api_key: str | None = None
    glm_api_key: str | None = None
    kimi_api_key: str | None = None
    max_agent_steps: int = 15
    max_route_repeats: int = 2

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""
    return Settings()
