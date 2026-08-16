import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=REPO_ROOT / ".env", env_file_encoding="utf-8", extra="ignore"
    )

    # LLM providers
    anthropic_api_key: str = ""
    gemini_api_key: str = ""
    router_model: str = "anthropic:claude-sonnet-5"
    agent_model: str = "anthropic:claude-sonnet-5"

    # Threat-intel sources (all optional; fixtures cover zero-key mode)
    vt_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    nvd_api_key: str = ""

    # Data resolver: prefer_cache | prefer_live | offline
    resolver_mode: str = "prefer_cache"

    # Paths (project-relative; overridable for tests)
    cache_dir: Path = REPO_ROOT / "data" / "cache"
    fixture_dir: Path = REPO_ROOT / "data" / "fixtures"
    attck_index: Path = REPO_ROOT / "data" / "attck_index.json"


def export_provider_keys(settings: Settings) -> None:
    # pydantic-ai reads LLM keys from the process environment, not from our .env-backed Settings
    if settings.anthropic_api_key:
        os.environ.setdefault("ANTHROPIC_API_KEY", settings.anthropic_api_key)
    if settings.gemini_api_key:
        os.environ.setdefault("GOOGLE_API_KEY", settings.gemini_api_key)
