"""Task 2 - Vulnerability Data Retrieval (OSV.dev, NVD, CISA KEV).

This module wires the real clients together from the settings in `.env`.
"""

from dataclasses import dataclass
from pathlib import Path

from src.retrieval.cache import SqliteCache
from src.retrieval.kev_client import KevClient
from src.retrieval.nvd_client import NvdClient
from src.retrieval.osv_client import OsvClient
from src.retrieval.rate_limiter import RateLimiter
from src.retrieval.vulnerability_service import VulnerabilityService

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CACHE_PATH = "cache/retrieval.sqlite3"
NVD_WINDOW_SECONDS = 30


@dataclass(frozen=True)
class Settings:
    nvd_api_key: str | None
    cache_path: Path


def read_settings(env) -> Settings:
    """Settings from environment variables (loaded from .env by the caller).

    A blank NVD_API_KEY means no key. A relative CVE_CACHE_PATH is resolved from the
    project root, so the cache does not depend on the folder the app starts in.
    """
    api_key = (env.get("NVD_API_KEY") or "").strip() or None
    cache_path = Path(env.get("CVE_CACHE_PATH") or DEFAULT_CACHE_PATH)
    if not cache_path.is_absolute():
        cache_path = PROJECT_ROOT / cache_path
    return Settings(nvd_api_key=api_key, cache_path=cache_path)


def build_service(session, env) -> VulnerabilityService:
    """The service with real clients sharing one HTTP session, one cache and one NVD limiter."""
    settings = read_settings(env)
    cache = SqliteCache(settings.cache_path)
    nvd_limit = 50 if settings.nvd_api_key else 5  # NVD: per 30 s, with or without a key
    limiter = RateLimiter(nvd_limit, NVD_WINDOW_SECONDS)
    return VulnerabilityService(
        osv=OsvClient(session, cache),
        nvd=NvdClient(session, cache, limiter, api_key=settings.nvd_api_key),
        kev=KevClient(session, cache),
    )
