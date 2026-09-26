"""
Central configuration for the Threat Intelligence Platform prototype.

Everything that could vary between environments (API keys, DB URL, model
name) lives here and is read from environment variables / a local .env
file. Nothing here should ever contain a hardcoded secret.
"""
from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Database -----------------------------------------------------------
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./threatintel.db")

    # Local ML spam classifier --------------------------------------------
    spam_threshold: float = float(os.getenv("SPAM_MODEL_THRESHOLD", "0.50"))

    # External intelligence -------------------------------------------------
    ipinfo_token: str = os.getenv("IPINFO_TOKEN", "")

    # CORS -----------------------------------------------------------------
    cors_origins: list[str] = [
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
        if o.strip()
    ]

    # Networking safety limits (used by the URL analyzer) -------------------
    url_fetch_timeout_seconds: float = 5.0
    url_fetch_max_redirects: int = 5
    url_fetch_max_bytes: int = 512_000

    @property
    def geo_enabled(self) -> bool:
        return bool(self.ipinfo_token)


@lru_cache
def get_settings() -> Settings:
    return Settings()
