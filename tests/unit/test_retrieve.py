"""Tests for the Task 2 entry point in src/retrieval/__init__.py (design spec sections 3, 8 and 10)."""

from pathlib import Path

from src.retrieval import PROJECT_ROOT, build_service, read_settings
from tests.unit.fakes import FakeSession

DEFAULT_CACHE = PROJECT_ROOT / "cache" / "retrieval.sqlite3"


# ---------------------------------------------------------------------------
# Settings from the environment (.env)
# ---------------------------------------------------------------------------

def test_defaults_without_any_settings():
    settings = read_settings({})

    assert settings.nvd_api_key is None
    assert settings.cache_path == DEFAULT_CACHE


def test_empty_api_key_counts_as_no_key():
    assert read_settings({"NVD_API_KEY": ""}).nvd_api_key is None
    assert read_settings({"NVD_API_KEY": "  "}).nvd_api_key is None


def test_api_key_is_read():
    assert read_settings({"NVD_API_KEY": "my-key"}).nvd_api_key == "my-key"


# The cache must not move around with the folder the app is started from.
def test_relative_cache_path_is_resolved_from_the_project_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    settings = read_settings({"CVE_CACHE_PATH": "cache/demo.sqlite3"})

    assert settings.cache_path == PROJECT_ROOT / "cache" / "demo.sqlite3"


def test_absolute_cache_path_is_kept(tmp_path):
    path = tmp_path / "elsewhere.sqlite3"

    assert read_settings({"CVE_CACHE_PATH": str(path)}).cache_path == path


def test_project_root_is_the_repository_folder():
    assert (PROJECT_ROOT / "src" / "retrieval" / "__init__.py").is_file()
    assert Path(PROJECT_ROOT / "requirements.txt").is_file()


# ---------------------------------------------------------------------------
# Building the clients
# ---------------------------------------------------------------------------

def test_without_key_nvd_allows_5_requests_per_30_seconds(tmp_path):
    service = build_service(FakeSession(), {"CVE_CACHE_PATH": str(tmp_path / "c.sqlite3")})

    limiter = service.nvd.limiter
    assert (limiter.max_calls, limiter.window_seconds) == (5, 30)
    assert service.nvd.headers == {}


def test_with_key_nvd_allows_50_requests_per_30_seconds(tmp_path):
    service = build_service(FakeSession(), {"NVD_API_KEY": "my-key", "CVE_CACHE_PATH": str(tmp_path / "c.sqlite3")})

    limiter = service.nvd.limiter
    assert (limiter.max_calls, limiter.window_seconds) == (50, 30)
    assert service.nvd.headers == {"apiKey": "my-key"}


def test_all_clients_share_one_session_and_one_cache_file(tmp_path):
    session = FakeSession()
    cache_path = tmp_path / "c.sqlite3"

    service = build_service(session, {"CVE_CACHE_PATH": str(cache_path)})

    assert service.osv.session is service.nvd.session is service.kev.session is session
    assert service.osv.cache.path == service.nvd.cache.path == service.kev.cache.path == cache_path
    assert cache_path.is_file()
