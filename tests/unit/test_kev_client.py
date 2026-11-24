"""Tests for src/retrieval/kev_client.py (design spec section 5, test IDs K1-K4)."""

import pytest
import requests

from src.retrieval.cache import SqliteCache
from src.retrieval.rate_limiter import RetrievalError
from src.retrieval.kev_client import KevClient
from tests.unit.fakes import FakeClock, FakeResponse, FakeSession, FakeSleep, load_fixture

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def make_client(tmp_path, responses, clock=None):
    session = FakeSession(responses)
    cache = SqliteCache(tmp_path / "cache.sqlite3", clock=clock or FakeClock())
    return KevClient(session, cache, sleep=FakeSleep()), session


def kev_response():
    return FakeResponse(200, load_fixture("kev_excerpt.json"))


# K1: Log4Shell is in the catalog of actively exploited vulnerabilities.
def test_log4shell_is_exploited(tmp_path):
    client, session = make_client(tmp_path, [kev_response()])

    exploited, is_stale = client.is_exploited("CVE-2021-44228")

    assert exploited is True
    assert is_stale is False
    assert session.calls[0]["method"] == "GET"
    assert session.calls[0]["url"] == KEV_URL


# K2: a CVE that is not in the catalog.
def test_cve_not_in_catalog_is_not_exploited(tmp_path):
    client, _ = make_client(tmp_path, [kev_response()])

    exploited, _ = client.is_exploited("CVE-0000-0000")

    assert exploited is False


def test_lookup_ignores_case(tmp_path):
    client, _ = make_client(tmp_path, [kev_response()])

    exploited, _ = client.is_exploited("cve-2021-44228")

    assert exploited is True


# K3: the catalog is downloaded once and reused (it is refreshed once a day).
def test_catalog_downloaded_once_for_many_lookups(tmp_path):
    client, session = make_client(tmp_path, [kev_response()])

    for _ in range(10):
        client.is_exploited("CVE-2021-44228")

    assert len(session.calls) == 1


def test_catalog_downloaded_again_after_a_day(tmp_path):
    clock = FakeClock()
    client, session = make_client(tmp_path, [kev_response(), kev_response()], clock)
    client.is_exploited("CVE-2021-44228")

    clock.advance(24 * 60 * 60)
    client.is_exploited("CVE-2021-44228")

    assert len(session.calls) == 2


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------

OFFLINE = [requests.ConnectionError("offline")] * 4  # first try + 3 retries


# K4: CISA is down and nothing is cached -> RetrievalError (the service then warns
# and treats the CVE as not known to be exploited).
def test_raises_when_cisa_is_down_and_nothing_cached(tmp_path):
    client, _ = make_client(tmp_path, OFFLINE)

    with pytest.raises(RetrievalError):
        client.is_exploited("CVE-2021-44228")


def test_falls_back_to_stale_catalog_when_cisa_is_down(tmp_path):
    clock = FakeClock()
    client, _ = make_client(tmp_path, [kev_response(), *OFFLINE], clock)
    client.is_exploited("CVE-2021-44228")
    clock.advance(24 * 60 * 60 * 3)

    exploited, is_stale = client.is_exploited("CVE-2021-44228")

    assert exploited is True
    assert is_stale is True


def test_bad_json_raises_retrieval_error(tmp_path):
    client, _ = make_client(tmp_path, [FakeResponse(200, ValueError("Expecting value"))])

    with pytest.raises(RetrievalError):
        client.is_exploited("CVE-2021-44228")


# If CISA ever changes the feed's format, that is a retrieval failure, not a crash.
def test_unexpected_feed_format_raises_retrieval_error(tmp_path):
    client, _ = make_client(tmp_path, [FakeResponse(200, {"title": "CISA Catalog", "entries": []})])

    with pytest.raises(RetrievalError):
        client.is_exploited("CVE-2021-44228")
