import os
from pathlib import Path

from dotenv import load_dotenv


# Load secrets from .env at the project root. The file is ignored by git.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


class Settings:
    """Small settings object to keep environment access in one place."""

    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


settings = Settings()
