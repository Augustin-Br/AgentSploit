import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


class Settings:
    """Small settings object to keep hardened-target environment access in one place."""

    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    mock_llm: bool = _env_bool("AGENTSPLOIT_MOCK_LLM", False)
    require_api_key: bool = _env_bool("HARDENED_REQUIRE_API_KEY", False)
    api_key: str | None = os.getenv("HARDENED_API_KEY") or os.getenv("AGENTSPLOIT_API_KEY")
    rate_limit_requests: int = _env_int("HARDENED_RATE_LIMIT_REQUESTS", 30)
    rate_limit_window_seconds: int = _env_int("HARDENED_RATE_LIMIT_WINDOW_SECONDS", 60)
    max_tool_calls_per_request: int = _env_int("HARDENED_MAX_TOOL_CALLS_PER_REQUEST", 3)
    max_response_chars: int = _env_int("HARDENED_MAX_RESPONSE_CHARS", 1200)


settings = Settings()
