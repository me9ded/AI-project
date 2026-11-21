"""Tests for the Task 2 entry point in src/retrieval/__init__.py (design spec sections 3, 8 and 10)."""

from pathlib import Path

import requests

from src.retrieval import PROJECT_ROOT, build_service, read_settings
from tests.unit.fakes import FakeClock, FakeResponse, FakeSession, FakeSleep, load_fixture

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


# ---------------------------------------------------------------------------
# End to end: real clients and service, saved API answers, no network
# ---------------------------------------------------------------------------

LOG4J_CORE = "org.apache.logging.log4j:log4j-core"
LOG4SHELL_INPUT = {
    "source_type": "raw-log",
    "packages": [
        {"name": LOG4J_CORE, "version": "2.14.1", "ecosystem": "Maven"},
        {"name": "org.apache.logging.log4j:log4j-api", "version": "2.14.1", "ecosystem": "Maven"},
    ],
    "cve_ids": [],
    "advisory_ids": [],
    "extraction_method": "regex",
    "raw_text": "...",
}


class RoutingSession:
    """Answers like the real APIs, from the saved fixtures, based on the request URL."""

    def __init__(self):
        self.calls = []

    def post(self, url, json=None, **kwargs):
        self.calls.append(("POST", url))
        assert url == "https://api.osv.dev/v1/query"
        if json["package"]["name"] == LOG4J_CORE:
            return FakeResponse(200, load_fixture("osv_query_log4j_core_2.14.1.json"))
        return FakeResponse(200, {})

    def get(self, url, params=None, **kwargs):
        self.calls.append(("GET", url))
        if url.startswith("https://services.nvd.nist.gov/"):
            if params["cveId"] == "CVE-2021-44228":
                return FakeResponse(200, load_fixture("nvd_CVE-2021-44228.json"))
            return FakeResponse(200, load_fixture("nvd_not_found.json"))
        if url.startswith("https://www.cisa.gov/"):
            return FakeResponse(200, load_fixture("kev_excerpt.json"))
        raise AssertionError(f"unexpected GET {url}")


def fake_time():
    """A clock and a sleep that moves it, so rate-limit waits take no real time."""
    clock = FakeClock()
    return {"clock": clock, "sleep": FakeSleep(clock)}


class OfflineSession:
    """Every request fails, like a laptop with no network."""

    def post(self, url, **kwargs):
        raise requests.ConnectionError("offline")

    def get(self, url, **kwargs):
        raise requests.ConnectionError("offline")


def test_log4shell_end_to_end_without_network(tmp_path):
    service = build_service(RoutingSession(), {"CVE_CACHE_PATH": str(tmp_path / "c.sqlite3")}, **fake_time())

    result = service.retrieve(LOG4SHELL_INPUT)

    records = {record.id: record for record in result.records}
    assert len(records) == 8
    assert records["CVE-2021-44228"].cvss_score == 10.0
    assert records["CVE-2021-44228"].severity == "CRITICAL"
    assert records["CVE-2021-44228"].in_kev is True
    assert records["CVE-2021-45046"].in_kev is True
    assert result.records[0].id == "CVE-2021-44228"          # highest score first
    assert result.recommended_upgrades == {LOG4J_CORE: "2.25.4"}
    assert result.incomplete is False
    assert result.warnings == []


# The offline demo: once the cache is warm, the same answers come back with no network.
def test_warm_cache_gives_the_same_answer_offline(tmp_path):
    env = {"CVE_CACHE_PATH": str(tmp_path / "c.sqlite3")}
    online = build_service(RoutingSession(), env, **fake_time()).retrieve(LOG4SHELL_INPUT)

    offline = build_service(OfflineSession(), env, **fake_time()).retrieve(LOG4SHELL_INPUT)

    assert offline == online


def test_second_run_makes_no_http_calls(tmp_path):
    session = RoutingSession()
    service = build_service(session, {"CVE_CACHE_PATH": str(tmp_path / "c.sqlite3")}, **fake_time())
    service.retrieve(LOG4SHELL_INPUT)
    calls_after_first_run = len(session.calls)

    service.retrieve(LOG4SHELL_INPUT)

    assert len(session.calls) == calls_after_first_run


# NFR5: the rate limit waits through the given sleep, so tests never really wait.
# Without a key, the 8 Log4j CVEs need more than 5 NVD calls in 30 s.
def test_rate_limit_waits_use_the_given_sleep(tmp_path):
    time = fake_time()
    service = build_service(RoutingSession(), {"CVE_CACHE_PATH": str(tmp_path / "c.sqlite3")}, **time)
    sleep = time["sleep"]

    service.retrieve(LOG4SHELL_INPUT)

    assert sleep.calls and max(sleep.calls) > 20   # one near-30 s limiter wait, faked


# ---------------------------------------------------------------------------
# The public retrieve(): one shared service per process, settings from .env
# ---------------------------------------------------------------------------

import pytest

import src.retrieval as retrieval


@pytest.fixture
def fresh_default(tmp_path, monkeypatch):
    """A clean default service that reads a .env in tmp_path and caches in tmp_path."""
    env_file = tmp_path / ".env"
    env_file.write_text(f"NVD_API_KEY=from-dotenv\nCVE_CACHE_PATH={tmp_path / 'c.sqlite3'}\n", encoding="utf-8")
    monkeypatch.setattr(retrieval, "ENV_FILE", env_file)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("CVE_CACHE_PATH", raising=False)
    retrieval.default_service.cache_clear()
    yield env_file
    retrieval.default_service.cache_clear()


def test_default_service_is_shared(fresh_default):
    assert retrieval.default_service() is retrieval.default_service()


def test_default_service_reads_the_env_file(fresh_default, tmp_path):
    service = retrieval.default_service()

    assert service.nvd.headers == {"apiKey": "from-dotenv"}
    assert service.osv.cache.path == tmp_path / "c.sqlite3"


def test_real_environment_variables_win_over_the_env_file(fresh_default, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "from-environment")

    assert retrieval.default_service().nvd.headers == {"apiKey": "from-environment"}


def test_retrieve_uses_the_default_service(monkeypatch):
    class StubService:
        def retrieve(self, extraction):
            return ("result for", extraction)

    monkeypatch.setattr(retrieval, "default_service", lambda: StubService())

    assert retrieval.retrieve({"packages": []}) == ("result for", {"packages": []})


# NFR9: NVD asks apps that use its API to show this notice; the UI (Task 4) imports it.
def test_nvd_notice_is_exported():
    assert retrieval.NVD_NOTICE == (
        "This product uses data from the NVD API but is not endorsed or certified by the NVD."
    )
