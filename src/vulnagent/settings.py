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
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-v4-flash"
    glm_base_url: str = "https://open.bigmodel.cn/api/paas/v4"
    glm_model: str = "glm-5.2"
    kimi_base_url: str = "https://api.moonshot.cn/v1"
    kimi_model: str = "kimi-k2.6"
    deepseek_input_cost_per_million: float | None = None
    deepseek_cached_input_cost_per_million: float | None = None
    deepseek_output_cost_per_million: float | None = None
    deepseek_cost_currency: str = "USD"
    glm_input_cost_per_million: float | None = 8.0
    glm_cached_input_cost_per_million: float | None = 2.0
    glm_output_cost_per_million: float | None = 28.0
    glm_cost_currency: str = "CNY"
    kimi_input_cost_per_million: float | None = 6.5
    kimi_cached_input_cost_per_million: float | None = 1.1
    kimi_output_cost_per_million: float | None = 27.0
    kimi_cost_currency: str = "CNY"
    llm_timeout_seconds: float = 30.0

    max_agent_steps: int = 15
    max_route_repeats: int = 2
    max_analysis_retries: int = 1

    storage_backend: str = "memory"
    sqlite_path: str = "artifacts/vulnagent.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return the cached process-wide settings instance."""

    return Settings()
