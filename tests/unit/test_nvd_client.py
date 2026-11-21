"""Tests for src/retrieval/nvd_client.py (design spec section 5, test IDs N1-N13)."""

from src.retrieval.cache import SqliteCache
from src.retrieval.nvd_client import NvdClient
from tests.unit.fakes import FakeClock, FakeResponse, FakeSession, FakeSleep, load_fixture

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class FakeLimiter:
    """Counts acquire() calls instead of rate limiting."""

    def __init__(self):
        self.acquired = 0

    def acquire(self):
        self.acquired += 1


def make_client(tmp_path, responses, api_key=None, clock=None):
    session = FakeSession(responses)
    limiter = FakeLimiter()
    cache = SqliteCache(tmp_path / "cache.sqlite3", clock=clock or FakeClock())
    client = NvdClient(session, cache, limiter, api_key=api_key, sleep=FakeSleep())
    return client, session, limiter


def log4shell_response():
    return FakeResponse(200, load_fixture("nvd_CVE-2021-44228.json"))


# N1: with an API key, it is sent in the apiKey header.
def test_api_key_is_sent_in_header(tmp_path):
    client, session, _ = make_client(tmp_path, [log4shell_response()], api_key="secret-key")

    client.get_cve("CVE-2021-44228")

    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == NVD_URL
    assert call["params"] == {"cveId": "CVE-2021-44228"}
    assert call["headers"] == {"apiKey": "secret-key"}
    assert call["timeout"] == 10


# N2: without a key, no apiKey header at all.
def test_no_api_key_header_without_key(tmp_path):
    client, session, _ = make_client(tmp_path, [log4shell_response()])

    client.get_cve("CVE-2021-44228")

    assert "apiKey" not in session.calls[0].get("headers", {})


# N3: score, CWEs and the English summary from the real Log4Shell record.
def test_parses_log4shell_record(tmp_path):
    client, _, _ = make_client(tmp_path, [log4shell_response()])

    cve, is_stale = client.get_cve("CVE-2021-44228")

    assert cve.id == "CVE-2021-44228"
    assert cve.cvss_score == 10.0
    assert "CWE-502" in cve.cwes
    assert cve.summary.startswith("Apache Log4j2")
    assert is_stale is False


# N12: the fixture also has a non-CVSS "ssvcV203" metric; it must not break scoring.
def test_non_cvss_metrics_are_ignored(tmp_path):
    response = load_fixture("nvd_CVE-2021-44228.json")
    assert "ssvcV203" in response["vulnerabilities"][0]["cve"]["metrics"]
    client, _, _ = make_client(tmp_path, [FakeResponse(200, response)])

    cve, _ = client.get_cve("CVE-2021-44228")

    assert cve.cvss_score == 10.0


# N8: an unknown CVE (HTTP 200, totalResults 0) is "not found", not an error.
def test_unknown_cve_returns_none(tmp_path):
    client, _, _ = make_client(tmp_path, [FakeResponse(200, load_fixture("nvd_not_found.json"))])

    cve, is_stale = client.get_cve("CVE-2021-99999999")

    assert cve is None
    assert is_stale is False


# Cache: a repeat lookup makes no request and does not use up the rate limit.
def test_repeat_lookup_uses_cache_and_skips_the_limiter(tmp_path):
    client, session, limiter = make_client(tmp_path, [log4shell_response()])

    client.get_cve("CVE-2021-44228")
    cve, _ = client.get_cve("CVE-2021-44228")

    assert len(session.calls) == 1
    assert limiter.acquired == 1
    assert cve.cvss_score == 10.0
