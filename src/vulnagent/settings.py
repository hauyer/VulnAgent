"""Environment-backed application settings."""

from functools import lru_cache

from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


class Settings(BaseSettings):
    """Runtime configuration for VulnAgent."""

    app_name: str = "VulnAgent"
    app_env: str = "development"
    log_level: str = "INFO"

    vulnagent_profile: str = "v03-source"

    llm_provider: str = "mock"

    deepseek_api_key: str | None = None
    glm_api_key: str | None = None
    kimi_api_key: str | None = None

    max_agent_steps: int = 15
    max_route_repeats: int = 2
    max_analysis_retries: int = 1

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return the cached process-wide settings instance."""

    return Settings()
