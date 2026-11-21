"""Task 2 - Vulnerability Data Retrieval (OSV.dev, NVD, CISA KEV).

Use it like this (Task 4's pipeline):

    from src.retrieval import retrieve
    result = retrieve(extraction)          # extraction = Task 1's JSON as a dict
    result.model_dump()                    # plain dict for Task 3 / the API

Settings come from `.env` in the project root (see `.env.example`); real
environment variables win over the file.
"""

import functools
import os
import time
from dataclasses import dataclass
from pathlib import Path

import requests
from dotenv import dotenv_values

from src.retrieval.cache import SqliteCache
from src.retrieval.kev_client import KevClient
from src.retrieval.nvd_client import NvdClient
from src.retrieval.osv_client import OsvClient
from src.retrieval.rate_limiter import RateLimiter
from src.retrieval.vulnerability_models import RetrievalResult, VulnerabilityRecord
from src.retrieval.vulnerability_service import VulnerabilityService

__all__ = ["retrieve", "RetrievalResult", "VulnerabilityRecord", "NVD_NOTICE"]

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
DEFAULT_CACHE_PATH = "cache/retrieval.sqlite3"
NVD_WINDOW_SECONDS = 30

# NVD asks every app that uses its API to show this notice (design spec NFR9).
NVD_NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD."


@dataclass(frozen=True)
class Settings:
    nvd_api_key: str | None
    cache_path: Path


def read_settings(env) -> Settings:
    """Settings from environment variables.

    A blank NVD_API_KEY means no key. A relative CVE_CACHE_PATH is resolved from the
    project root, so the cache does not depend on the folder the app starts in.
    """
    api_key = (env.get("NVD_API_KEY") or "").strip() or None
    cache_path = Path(env.get("CVE_CACHE_PATH") or DEFAULT_CACHE_PATH)
    if not cache_path.is_absolute():
        cache_path = PROJECT_ROOT / cache_path
    return Settings(nvd_api_key=api_key, cache_path=cache_path)


def build_service(session, env, clock=time.monotonic, sleep=time.sleep) -> VulnerabilityService:
    """The service with real clients sharing one HTTP session, one cache and one NVD limiter.

    `clock` and `sleep` drive the rate limiter and retry waits; tests pass fakes.
    """
    settings = read_settings(env)
    cache = SqliteCache(settings.cache_path)
    nvd_limit = 50 if settings.nvd_api_key else 5  # NVD: per 30 s, with or without a key
    limiter = RateLimiter(nvd_limit, NVD_WINDOW_SECONDS, clock=clock, sleep=sleep)
    return VulnerabilityService(
        osv=OsvClient(session, cache, sleep=sleep),
        nvd=NvdClient(session, cache, limiter, api_key=settings.nvd_api_key, sleep=sleep),
        kev=KevClient(session, cache, sleep=sleep),
    )


@functools.lru_cache(maxsize=1)
def default_service() -> VulnerabilityService:
    """One service per process, so every request shares the same NVD rate limiter."""
    env = {**dotenv_values(ENV_FILE), **os.environ}  # read .env without changing os.environ
    return build_service(requests.Session(), env)


def retrieve(extraction: dict) -> RetrievalResult:
    """Look up the vulnerabilities for Task 1's extraction (design spec section 4)."""
    return default_service().retrieve(extraction)
