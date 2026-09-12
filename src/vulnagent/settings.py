"""Environment-backed application settings."""

from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import field_validator
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
    kimi_model: str = "kimi-k3"
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

    # The course LLM vulnerability laboratory is deliberately isolated from
    # the cloud-provider router above.  It only accepts an HTTP loopback URL
    # and never sends an API key.
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_deepseek_model: str = "deepseek-r1:1.5b"
    ollama_qwen_model: str = "qwen2.5:1.5b-instruct-q4_K_M"
    ollama_scan_timeout_seconds: float = 90.0
    ollama_scan_max_tokens: int = 192
    # 0 forces CPU inference.  The current teaching machine's Ollama CUDA
    # runner is incompatible with its installed NVIDIA driver; set -1 after
    # updating the driver to let Ollama choose GPU layers automatically.
    ollama_scan_num_gpu: int = 0
    ollama_scan_response_limit: int = 6000
    ollama_scan_log_excerpt: int = 280

    # Offline, authorization-gated binary reverse workbench. Relative paths
    # are resolved from the repository root by the composition layer.
    binary_reverse_enabled: bool = True
    binary_reverse_output_dir: str = "artifacts/reverse"
    binary_radare2_path: str = "tools/radare2/radare2-6.2.2-w64/bin/radare2.exe"
    binary_upx_path: str = "tools/upx/upx-5.2.1-win64/upx.exe"
    binary_reverse_timeout_seconds: float = 30.0
    binary_reverse_max_functions: int = 24
    binary_reverse_max_pseudocode_chars: int = 12000

    max_agent_steps: int = 15
    max_route_repeats: int = 2
    max_analysis_retries: int = 1

    storage_backend: str = "memory"
    sqlite_path: str = "artifacts/vulnagent.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @field_validator(
        "deepseek_input_cost_per_million",
        "deepseek_cached_input_cost_per_million",
        "deepseek_output_cost_per_million",
        "glm_input_cost_per_million",
        "glm_cached_input_cost_per_million",
        "glm_output_cost_per_million",
        "kimi_input_cost_per_million",
        "kimi_cached_input_cost_per_million",
        "kimi_output_cost_per_million",
        mode="before",
    )
    @classmethod
    def _empty_cost_string_to_none(cls, value: object) -> object:
        """Treat blank ``.env`` cost overrides as unset, matching the docs."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("ollama_base_url")
    @classmethod
    def _require_loopback_ollama(cls, value: str) -> str:
        """Reject cloud or LAN destinations for the local-only lab."""

        normalized = value.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "ollama_base_url must be a credential-free HTTP loopback URL"
            )
        return normalized


@lru_cache
def get_settings() -> Settings:
    """Return the cached process-wide settings instance."""

    return Settings()
